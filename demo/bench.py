"""Overhead of the gateway: median round trip of one tool call, direct vs through mcpgate.

    python demo/bench.py [calls]

Both paths use real processes and stdio pipes. The call budget is raised for the
measurement, since the demo policy would stop the 21st call to the same tool.
"""

from __future__ import annotations

import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def median_ms(argv: list[str], tool: str, env: dict, calls: int) -> float:
    p = subprocess.Popen(argv, cwd=ROOT, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)

    def rpc(rid: int, method: str, params: dict) -> dict:
        p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}) + "\n")
        p.stdin.flush()
        while (msg := json.loads(p.stdout.readline())).get("id") != rid:
            pass
        return msg

    rpc(0, "initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "bench", "version": "1"}})
    times = []
    for i in range(1, calls + 1):
        t = time.perf_counter()
        msg = rpc(i, "tools/call", {"name": tool, "arguments": {}})
        times.append(time.perf_counter() - t)
        assert not msg["result"].get("isError"), msg
    p.stdin.close()
    p.wait()
    return statistics.median(times) * 1000


def main(calls: int = 300) -> None:
    tmp = Path(tempfile.mkdtemp(prefix="mcpgate-bench-"))
    try:
        shutil.copytree(ROOT / "demo" / "workspace", tmp / "workspace")
        policy = (ROOT / "gateway.toml").read_text(encoding="utf-8")
        policy = policy.replace("[gateway]\n", f'[gateway]\nroot = "{ROOT.as_posix()}"\n', 1)
        policy = policy.replace("max_calls = 50", "max_calls = 1000000").replace("max_calls_per_tool = 20", "max_calls_per_tool = 1000000")
        policy = policy.replace('audit_log = "audit.jsonl"', 'audit_log = "audit.jsonl"  # in the temporary folder')
        (tmp / "bench.toml").write_text(policy, encoding="utf-8")
        shutil.copy(ROOT / "mcp.lock.json", tmp / "mcp.lock.json")
        env = {**os.environ, "WORKSPACE": str(tmp / "workspace"), "PYTHONPATH": str(ROOT / "src")}
        for run in (1, 2):
            direct = median_ms([sys.executable, "demo/servers/mail.py"], "read_inbox", env, calls)
            gated = median_ms([sys.executable, "-m", "mcpgate", "run", "--policy", str(tmp / "bench.toml"),
                               "--profile", "inbox_summary"], "mail.read_inbox", env, calls)
            print(f"run {run}: direct {direct:.3f} ms · through the gateway {gated:.3f} ms · overhead {gated - direct:.3f} ms"
                  f"  (median of {calls} calls, Python {sys.version.split()[0]})")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 300)
