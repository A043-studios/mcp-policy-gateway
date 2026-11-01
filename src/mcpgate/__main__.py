"""Command line.

  python -m mcpgate run    --policy gateway.toml --profile inbox_summary
  python -m mcpgate review --policy gateway.toml      show tools, screening hints and drift
  python -m mcpgate lock   --policy gateway.toml      pin what you just reviewed
"""

from __future__ import annotations

import argparse
import sys

from .audit import Audit
from .config import Policy
from .pinning import LockFile, command_fingerprint, screen_description, tool_fingerprint
from .policy import recipient_fields
from .stdio import Upstream


def _collect(policy: Policy, skip: set[str] = frozenset()) -> dict[str, tuple[list[str], dict, list[dict]]]:
    out = {}
    for name, srv in policy.servers.items():
        if name in skip:
            continue
        up = Upstream(name, srv.command, env=srv.env, cwd=str(policy.base_dir))
        try:
            up.initialize()
            out[name] = (srv.command, srv.env, up.list_tools())
        finally:
            up.close()
    return out


def review(policy: Policy, start_changed: bool = False) -> int:
    lock = LockFile.load(policy.lockfile)

    def cmd_state(name: str) -> str:
        if not lock:
            return "-"
        if name not in lock.servers:
            return "NEW"
        srv = policy.servers[name]
        return "ok" if lock.command_ok(name, command_fingerprint(srv.command, srv.env)) else "CHANGED"

    # Starting a server is running its command. A changed or new command is code nobody
    # reviewed yet (MCPoison), so review does not run it unless asked to.
    held = set() if start_changed else {n for n in policy.servers if cmd_state(n) in ("NEW", "CHANGED")}
    servers = _collect(policy, skip=held)
    all_names = {t["name"] for _, _, tools in servers.values() for t in tools}
    drift = 0
    for name, srv in policy.servers.items():
        state = cmd_state(name)
        drift += state in ("NEW", "CHANGED")
        print(f"\n{name}  ({srv.trust})  command: {' '.join(srv.command)}  [{state}]")
        if name in held:
            print("           not started. Check the command, then run: review --start-changed")
            continue
        for t in servers[name][2]:
            state = lock.tool_status(name, t) if lock else "unlocked"
            drift += state != "pinned"
            hints = screen_description(t, all_names)
            cfg = srv.tools.get(t["name"])
            props = (t.get("inputSchema") or {}).get("properties")
            if cfg and cfg.recipient_args and isinstance(props, dict):
                extra = recipient_fields(cfg.recipient_args, set(props))[len(cfg.recipient_args):]
                if extra:
                    hints.append("recipient-like fields not in recipient_args (checked as recipients): " + ", ".join(extra))
            print(f"  {state:8} {name}.{t['name']}" + (f"   ! {'; '.join(hints)}" if hints else ""))
            if state != "pinned":
                print("           " + (t.get("description") or "").replace("\n", " ")[:300])
    print(f"\n{drift} tool(s) or command(s) differ from the lock file." if lock else "\nNo lock file yet. Review, then run: lock")
    return 1 if drift else 0


def lock(policy: Policy) -> int:
    servers = _collect(policy)
    data = {name: {"command": command_fingerprint(argv, env),
                   "tools": {t["name"]: tool_fingerprint(t) for t in tools}}
            for name, (argv, env, tools) in servers.items()}
    LockFile(data).save(policy.lockfile)
    print(f"Pinned {sum(len(v['tools']) for v in data.values())} tools from {len(data)} servers in {policy.lockfile.name}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="mcpgate", description="Policy gateway for the Model Context Protocol")
    p.add_argument("command", choices=["run", "review", "lock"])
    p.add_argument("--policy", default="gateway.toml")
    p.add_argument("--profile", default="default")
    p.add_argument("--verbose", action="store_true", help="echo audit events to stderr")
    p.add_argument("--start-changed", action="store_true",
                   help="review: also start servers whose command is new or differs from the lock file")
    a = p.parse_args(argv)
    policy = Policy.load(a.policy)
    if a.command == "review":
        return review(policy, a.start_changed)
    if a.command == "lock":
        return lock(policy)
    from .gateway import Gateway
    Gateway(policy, a.profile, audit=Audit(policy.audit_log, echo=a.verbose)).serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())
