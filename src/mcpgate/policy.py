"""The decision function. Pure: same inputs, same answer, no I/O.

A tool call is allowed, denied, or needs a human. The checks run in a fixed
order and the first that objects wins, so every decision has exactly one reason.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .config import Policy, ToolPolicy
from .sanitize import destinations, host_allowed, unparsed_recipients, unreadable_destinations

U, D = "U", "D"


@dataclass
class ToolInfo:
    """What the gateway believes about one tool, after policy and annotations."""
    qualified: str             # server.tool
    server: str
    name: str
    labels: set[str]           # brought into the session by the tool's output
    effect: str                # none | communication | state | destructive
    recipient_args: list[str] = field(default_factory=list)
    owner_reply_ok: bool = False
    status: str = "pinned"     # pinned | changed | new | unlocked
    arg_names: set[str] | None = None   # properties of the reviewed input schema, if it lists any


@dataclass
class Session:
    labels: set[str] = field(default_factory=set)   # monotone: labels never leave
    calls: int = 0
    per_tool: dict[str, int] = field(default_factory=dict)


@dataclass
class Decision:
    verdict: str               # allow | deny | approve
    control: str = ""
    reason: str = ""


_RECIPIENT_WORDS = {"to", "cc", "bcc", "recipient", "recipients"}
_RECIPIENT_NAMES = {"url", "uri", "webhook", "webhookurl", "endpoint", "callbackurl", "destination",
                    "email", "emailaddress"}


def recipient_fields(configured: list[str], arg_names: set[str] | None) -> list[str]:
    """The configured recipient fields plus every schema field whose name says it is one.

    A mail tool with a ``bcc`` field nobody listed must not carry data past the
    allowlist because the policy forgot to classify it.
    """
    if not configured:
        return []
    def looks_like(name: str) -> bool:
        words = set(re.findall(r"[a-z]+", re.sub(r"([a-z])([A-Z])", r"\1 \2", name).lower()))
        return bool(words & _RECIPIENT_WORDS) or re.sub(r"[^a-z]", "", name.lower()) in _RECIPIENT_NAMES
    return configured + sorted(a for a in (arg_names or ()) if a not in configured and looks_like(a))


def derive(server_trust: str, tool: dict, configured: ToolPolicy | None, qualified: str) -> ToolInfo:
    """Turn policy and (only from internal servers) annotations into labels.

    Annotations are claims made by the server. A third-party server can lie, so
    its claims are ignored and the worst case is assumed: its output is
    untrusted and calling it can carry data out.
    """
    server, name = qualified.split(".", 1)
    cfg = configured or ToolPolicy()
    ann = tool.get("annotations") or {}
    if server_trust == "internal":
        read_only = ann.get("readOnlyHint", False)
        destructive = ann.get("destructiveHint", True)
        open_world = ann.get("openWorldHint", True)
        if read_only:   # a read that reaches the open world still carries its arguments out
            default_effect = "communication" if open_world else "none"
        else:
            default_effect = "destructive" if destructive else ("communication" if open_world else "state")
        default_labels = {U} if open_world else set()
    else:
        default_effect, default_labels = "communication", {U}
    props = (tool.get("inputSchema") or {}).get("properties")
    return ToolInfo(
        qualified=qualified, server=server, name=name,
        labels=cfg.labels if cfg.labels is not None else default_labels,
        effect=cfg.effect or default_effect,
        recipient_args=cfg.recipient_args, owner_reply_ok=cfg.owner_reply_ok,
        arg_names=set(props) if isinstance(props, dict) else None,
    )


def is_owner_reply(info: ToolInfo, args: dict, owner: str) -> bool:
    if not (info.owner_reply_ok and owner and info.recipient_args):
        return False
    targets = [args.get(a) for a in recipient_fields(info.recipient_args, info.arg_names) if args.get(a)]
    return bool(targets) and all(str(t).strip().lower() == owner.lower() for t in targets)


def decide(info: ToolInfo, args: dict, session: Session, policy: Policy, profile: str) -> Decision:
    c = policy.controls

    if c.circuit_breaker:
        if session.calls >= policy.max_calls:
            return Decision("deny", "circuit_breaker", f"session limit of {policy.max_calls} calls reached")
        if session.per_tool.get(info.qualified, 0) >= policy.max_calls_per_tool:
            return Decision("deny", "circuit_breaker", f"limit of {policy.max_calls_per_tool} calls to {info.qualified}")

    if c.pinning and info.status != "pinned":
        return Decision("deny", "pinning", f"tool is {info.status}: its definition does not match the reviewed lock file")

    if c.least_privilege and info.qualified not in policy.profiles.get(profile, set()):
        return Decision("deny", "least_privilege", f"{info.qualified!r} is not in profile {profile!r}")

    owner_reply = is_owner_reply(info, args, policy.owner)

    if c.egress and info.effect != "none":
        # Arguments the reviewed schema does not list were never classified by anyone.
        unknown = sorted(set(args) - info.arg_names) if info.arg_names is not None else []
        if unknown:
            return Decision("deny", "egress_allowlist", "argument outside the reviewed schema: " + ", ".join(unknown))
        # Known recipient fields are checked exactly, and must be readable in full. For
        # tools without them, every address and URL in any argument counts as a destination.
        fields = recipient_fields(info.recipient_args, info.arg_names)
        where = {a: args.get(a) for a in fields} if fields else args
        unclear = unparsed_recipients(where) if fields else unreadable_destinations(where)
        if unclear:
            return Decision("deny", "egress_allowlist", "recipient not understood: " + ", ".join(unclear)[:200])
        foreign = sorted({h for h in destinations(where) if not host_allowed(h, policy.egress_allow)})
        if foreign:
            return Decision("deny", "egress_allowlist", "destination outside allowlist: " + ", ".join(foreign))

    if c.flow:
        if info.effect == "communication" and not owner_reply and {U, D} <= session.labels:
            return Decision("approve", "rule_of_two",
                            "session holds untrusted input and private data; this call sends data out")
        if info.effect in ("state", "destructive") and U in session.labels:
            return Decision("approve", "integrity",
                            "session holds untrusted input; this call changes state")

    if info.effect == "destructive":
        return Decision("approve", "destructive", "destructive action")

    return Decision("allow")


def record(info: ToolInfo, session: Session) -> None:
    """After a call ran: count it and let its output taint the session."""
    session.calls += 1
    session.per_tool[info.qualified] = session.per_tool.get(info.qualified, 0) + 1
    session.labels |= info.labels
