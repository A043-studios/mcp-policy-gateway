"""JSON-RPC 2.0 over stdio, the way MCP frames it: one JSON object per line.

Two pieces: helpers to read and write messages on a stream, and ``Upstream``,
a client connection to one MCP server running as a child process.

Security note: the server is started from an argv list, never through a shell,
and the exact argv is pinned in the lock file (see pinning.py). Starting a
server is running code; the gateway refuses to start one whose command changed.
"""

from __future__ import annotations

import itertools
import json
import os
import queue
import subprocess
import sys
import threading
from typing import IO, Any

PROTOCOL_VERSION = "2025-11-25"
STATELESS_VERSION = "2026-07-28"
SUPPORTED_VERSIONS = ("2025-06-18", "2025-11-25", "2026-07-28")


def resolve_argv(argv: list[str]) -> list[str]:
    """``{python}`` stands for the interpreter running the gateway (portable demo configs).
    The lock file pins the unresolved argv, so it is the same on every machine."""
    return [sys.executable if a == "{python}" else a for a in argv]


class RpcError(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code, self.message, self.data = code, message, data


def write_message(stream: IO[str], message: dict) -> None:
    # MCP stdio: messages are newline-delimited and MUST NOT contain embedded newlines.
    stream.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n")
    stream.flush()


def read_message(stream: IO[str]) -> dict | None:
    while True:
        line = stream.readline()
        if not line:
            return None
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return {"jsonrpc": "2.0", "id": None, "_parse_error": line[:200]}


class Upstream:
    """A connection to one MCP server child process (the gateway is its client)."""

    def __init__(self, name: str, argv: list[str], env: dict[str, str] | None = None,
                 cwd: str | None = None, timeout: float = 30.0):
        self.name, self.argv, self.timeout = name, argv, timeout
        self._ids = itertools.count(1)
        self._pending: dict[int, queue.Queue] = {}
        self._lock = threading.Lock()
        self.notifications: queue.Queue = queue.Queue()
        self.proc = subprocess.Popen(
            resolve_argv(argv), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr,
            text=True, encoding="utf-8", bufsize=1, cwd=cwd,
            env={**os.environ, **(env or {})}, shell=False,
        )
        threading.Thread(target=self._reader, daemon=True).start()
        self.server_info: dict = {}

    def _reader(self) -> None:
        assert self.proc.stdout is not None
        while (msg := read_message(self.proc.stdout)) is not None:
            if "id" in msg and ("result" in msg or "error" in msg):
                with self._lock:
                    q = self._pending.pop(msg["id"], None)
                if q is not None:
                    q.put(msg)
            elif "method" in msg and "id" not in msg:
                self.notifications.put(msg)
            # Server-to-client requests (sampling, roots) are not forwarded: the
            # gateway answers them with an error so an upstream server cannot
            # drive the model or read the client's roots through the gateway.
            elif "method" in msg and "id" in msg:
                self._send({"jsonrpc": "2.0", "id": msg["id"],
                            "error": {"code": -32601, "message": "not available through the gateway"}})

    def _send(self, message: dict) -> None:
        assert self.proc.stdin is not None
        with self._lock:
            write_message(self.proc.stdin, message)

    def request(self, method: str, params: dict | None = None) -> dict:
        rid = next(self._ids)
        q: queue.Queue = queue.Queue(maxsize=1)
        with self._lock:
            self._pending[rid] = q
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        try:
            msg = q.get(timeout=self.timeout)
        except queue.Empty:
            raise RpcError(-32001, f"upstream {self.name} timed out on {method}") from None
        if "error" in msg:
            err = msg["error"]
            raise RpcError(err.get("code", -32603), err.get("message", "upstream error"), err.get("data"))
        return msg["result"]

    def notify(self, method: str, params: dict | None = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def initialize(self) -> dict:
        result = self.request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcpgate", "version": "1.0.0"},
        })
        self.notify("notifications/initialized")
        self.server_info = result.get("serverInfo", {})
        return result

    def list_tools(self) -> list[dict]:
        tools, cursor = [], None
        while True:
            result = self.request("tools/list", {"cursor": cursor} if cursor else {})
            tools += result.get("tools", [])
            cursor = result.get("nextCursor")
            if not cursor:
                return tools

    def drain_notifications(self) -> list[dict]:
        out = []
        while not self.notifications.empty():
            out.append(self.notifications.get_nowait())
        return out

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.wait(timeout=3)
        except Exception:
            self.proc.kill()
