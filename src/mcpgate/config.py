"""The policy file: which servers exist, what their tools may do, which task may use what.

Everything security-relevant lives here, as data a person can review, and none of
it can be changed by the model or by an MCP server.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

EFFECTS = ("none", "communication", "state", "destructive")


@dataclass
class ToolPolicy:
    labels: set[str] | None = None        # what the tool's OUTPUT brings into the session: U, D
    effect: str | None = None             # none | communication | state | destructive
    recipient_args: list[str] = field(default_factory=list)   # args naming where data goes
    owner_reply_ok: bool = False          # sending to the task owner is not an external effect


@dataclass
class ServerConfig:
    name: str
    command: list[str]
    trust: str = "third_party"            # internal | third_party
    env: dict[str, str] = field(default_factory=dict)
    tools: dict[str, ToolPolicy] = field(default_factory=dict)


@dataclass
class Controls:
    pinning: bool = True
    least_privilege: bool = True
    egress: bool = True
    sanitise: bool = True
    flow: bool = True                     # Rule of Two plus the integrity rule
    approval: str = "elicit"              # elicit | deny | stamp
    outbound_filter: bool = True
    circuit_breaker: bool = True


@dataclass
class Policy:
    servers: dict[str, ServerConfig]
    profiles: dict[str, set[str]]
    egress_allow: list[str]
    owner: str
    lockfile: Path
    audit_log: Path | None
    max_calls: int = 50
    max_calls_per_tool: int = 20
    initial_labels: set[str] = field(default_factory=lambda: {"D"})   # the request itself is private
    controls: Controls = field(default_factory=Controls)
    base_dir: Path = Path(".")

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        path = Path(path).resolve()
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
        gw = raw.get("gateway", {})
        servers = {}
        for name, s in raw.get("servers", {}).items():
            if "." in name:
                raise ValueError(f"server name {name!r} must not contain '.'")
            tools = {}
            for tname, t in s.get("tools", {}).items():
                effect = t.get("effect")
                if effect is not None and effect not in EFFECTS:
                    raise ValueError(f"{name}.{tname}: unknown effect {effect!r}")
                tools[tname] = ToolPolicy(
                    labels=set(t["labels"]) if "labels" in t else None,
                    effect=effect,
                    recipient_args=list(t.get("recipient_args", [])),
                    owner_reply_ok=bool(t.get("owner_reply_ok", False)),
                )
            servers[name] = ServerConfig(name=name, command=list(s["command"]),
                                         trust=s.get("trust", "third_party"),
                                         env=dict(s.get("env", {})), tools=tools)
        controls = Controls(**raw.get("controls", {}))
        root = (path.parent / gw.get("root", ".")).resolve()   # where server commands run
        return cls(
            servers=servers,
            profiles={k: set(v.get("allow", [])) for k, v in raw.get("profiles", {}).items()},
            egress_allow=[d.lower() for d in gw.get("egress_allow", [])],
            owner=gw.get("owner", ""),
            lockfile=(path.parent / gw.get("lockfile", "mcp.lock.json")),
            audit_log=(path.parent / gw["audit_log"]) if gw.get("audit_log") else None,
            max_calls=int(gw.get("max_calls", 50)),
            max_calls_per_tool=int(gw.get("max_calls_per_tool", 20)),
            initial_labels=set(gw.get("initial_labels", ["D"])),
            controls=controls,
            base_dir=root,
        )
