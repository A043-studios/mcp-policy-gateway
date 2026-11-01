"""A tiny MCP stdio server for the demo: just enough of the protocol, no dependencies.

Speaks the 2025-11-25 handshake (initialize) and answers tools/list and tools/call.
"""

from __future__ import annotations

import json
import sys
from typing import Callable


class Server:
    def __init__(self, name: str, version: str = "1.0.0"):
        self.name, self.version = name, version
        self.tools: dict[str, tuple[dict, Callable[..., str]]] = {}

    def tool(self, name: str, description: str, schema: dict, annotations: dict | None = None):
        def register(fn: Callable[..., str]):
            definition = {"name": name, "description": description, "inputSchema": schema}
            if annotations:
                definition["annotations"] = annotations
            self.tools[name] = (definition, fn)
            return fn
        return register

    def _handle(self, method: str, params: dict):
        if method == "initialize":
            return {"protocolVersion": params.get("protocolVersion", "2025-11-25"),
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": self.name, "version": self.version}}
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": [d for d, _ in self.tools.values()]}
        if method == "tools/call":
            name = params.get("name")
            if name not in self.tools:
                return {"content": [{"type": "text", "text": f"unknown tool {name}"}], "isError": True}
            try:
                text = self.tools[name][1](**(params.get("arguments") or {}))
                return {"content": [{"type": "text", "text": text}]}
            except Exception as exc:
                return {"content": [{"type": "text", "text": f"error: {exc}"}], "isError": True}
        raise LookupError(method)

    def run(self) -> None:
        for line in sys.stdin:
            if not line.strip():
                continue
            msg = json.loads(line)
            if "id" not in msg or "method" not in msg:
                continue
            try:
                reply = {"jsonrpc": "2.0", "id": msg["id"], "result": self._handle(msg["method"], msg.get("params") or {})}
            except LookupError:
                reply = {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "method not found"}}
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()
