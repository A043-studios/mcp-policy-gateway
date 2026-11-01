"""The gateway: an MCP server to the client, an MCP client to every real server.

    client (Claude, an IDE, an agent)  <--stdio-->  mcpgate  <--stdio-->  server A, B, C

It shows the model only reviewed tools, decides every call, cleans every result
and writes everything down. The model proposes; the gateway decides.
"""

from __future__ import annotations

import sys
from collections import deque
from typing import IO

from . import approval
from .audit import Audit
from .config import Policy
from .pinning import VISIBLE_FIELDS, LockFile, command_fingerprint
from .policy import Decision, Session, ToolInfo, decide, derive, is_owner_reply, recipient_fields, record
from .sanitize import clean, mark_untrusted, strip_foreign_links
from .stdio import (PROTOCOL_VERSION, STATELESS_VERSION, SUPPORTED_VERSIONS, RpcError, Upstream,
                    read_message, write_message)

VERSION_KEY = "io.modelcontextprotocol/protocolVersion"
CAPS_KEY = "io.modelcontextprotocol/clientCapabilities"
SERVER_INFO = {"name": "mcpgate", "title": "A+43 MCP policy gateway", "version": "1.0.0"}


class Gateway:
    def __init__(self, policy: Policy, profile: str, stdin: IO[str] = sys.stdin, stdout: IO[str] = sys.stdout,
                 audit: Audit | None = None):
        self.policy, self.profile = policy, profile
        self.stdin, self.stdout = stdin, stdout
        self.audit = audit or Audit(policy.audit_log)
        self.lock = LockFile.load(policy.lockfile)
        self.session = Session(labels=set(policy.initial_labels))
        self.signer = approval.StateSigner()
        self.upstreams: dict[str, Upstream] = {}
        self.tools: dict[str, tuple[ToolInfo, dict]] = {}   # qualified name -> (info, raw definition)
        self.client_can_elicit = False
        self._backlog: deque[dict] = deque()
        self._next_id = 0
        self._started = False
        self._quarantine_logged: set[tuple[str, str]] = set()

    # ------------------------------------------------------------------ upstreams
    def start(self) -> None:
        if self._started:
            return
        self._started = True
        for name, srv in self.policy.servers.items():
            fp = command_fingerprint(srv.command, srv.env)
            if self.policy.controls.pinning and self.lock and not self.lock.command_ok(name, fp):
                self.audit.log("server_quarantined", server=name, reason="start command differs from lock file")
                continue
            try:
                up = Upstream(name, srv.command, env=srv.env, cwd=str(self.policy.base_dir))
                up.initialize()
                self.upstreams[name] = up
            except Exception as exc:   # a broken server must not take the gateway down
                self.audit.log("server_failed", server=name, reason=str(exc)[:200])
        self.refresh_tools()

    def refresh_tools(self) -> None:
        self.tools = {}
        for name, up in self.upstreams.items():
            up.drain_notifications()
            srv = self.policy.servers[name]
            for raw in up.list_tools():
                qualified = f"{name}.{raw['name']}"
                info = derive(srv.trust, raw, srv.tools.get(raw["name"]), qualified)
                info.status = self.lock.tool_status(name, raw) if self.lock else "unlocked"
                if info.status != "pinned" and (qualified, info.status) not in self._quarantine_logged:
                    self._quarantine_logged.add((qualified, info.status))
                    self.audit.log("tool_quarantined", tool=qualified, status=info.status)
                self.tools[qualified] = (info, raw)

    def _maybe_refresh(self) -> None:
        if any(not up.notifications.empty() for up in self.upstreams.values()):
            self.refresh_tools()

    def visible_tools(self) -> list[dict]:
        c, out = self.policy.controls, []
        allowed = self.policy.profiles.get(self.profile, set())
        for qualified, (info, raw) in sorted(self.tools.items()):
            if c.pinning and info.status != "pinned":
                continue
            if c.least_privilege and qualified not in allowed:
                continue
            # only the fields the lock file covers: anything else would reach the client unreviewed
            out.append({**{k: raw[k] for k in VISIBLE_FIELDS if k in raw}, "name": qualified})
        return out

    # ------------------------------------------------------------------ client I/O
    def _send(self, msg: dict) -> None:
        write_message(self.stdout, msg)

    def _ask_client(self, method: str, params: dict) -> dict | None:
        """Send a request to the client and wait for its answer (legacy elicitation)."""
        self._next_id += 1
        rid = f"gw-{self._next_id}"
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        while (msg := read_message(self.stdin)) is not None:
            if msg.get("id") == rid and ("result" in msg or "error" in msg):
                return msg.get("result")
            self._backlog.append(msg)
        return None

    def serve(self) -> None:
        while True:
            msg = self._backlog.popleft() if self._backlog else read_message(self.stdin)
            if msg is None:
                break
            if "method" not in msg:
                continue
            if "id" not in msg:
                continue          # notifications from the client need no answer
            try:
                result = self.handle(msg["method"], msg.get("params") or {})
                self._send({"jsonrpc": "2.0", "id": msg["id"], "result": result})
            except RpcError as e:
                self._send({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": e.code, "message": e.message}})
        self.close()

    def close(self) -> None:
        for up in self.upstreams.values():
            up.close()

    # ------------------------------------------------------------------ methods
    def handle(self, method: str, params: dict) -> dict:
        meta = params.get("_meta") or {}
        stateless = meta.get(VERSION_KEY) == STATELESS_VERSION
        if stateless:
            self.client_can_elicit = "elicitation" in (meta.get(CAPS_KEY) or {})

        if method == "initialize":
            self.client_can_elicit = "elicitation" in (params.get("capabilities") or {})
            asked = params.get("protocolVersion")
            self.start()
            return {"protocolVersion": asked if asked in SUPPORTED_VERSIONS[:2] else PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": SERVER_INFO,
                    "instructions": "Tools are mediated by a policy gateway. Blocked calls return an error that names the control."}
        if method == "server/discover":
            self.start()
            return {"supportedVersions": list(SUPPORTED_VERSIONS), "capabilities": {"tools": {"listChanged": True}},
                    "_meta": {"io.modelcontextprotocol/serverInfo": SERVER_INFO},
                    "resultType": "complete", "ttlMs": 0, "cacheScope": "private"}
        if method == "ping":
            return {}

        self.start()
        if method == "tools/list":
            self.refresh_tools()
            result = {"tools": self.visible_tools()}
            if stateless:
                result.update(resultType="complete", ttlMs=0, cacheScope="private")
            return result
        if method == "tools/call":
            self._maybe_refresh()
            result = self.call(params, stateless)
            if stateless and "resultType" not in result:
                result["resultType"] = "complete"
            return result
        if method in ("resources/list", "prompts/list", "resources/templates/list"):
            key = {"resources/list": "resources", "prompts/list": "prompts",
                   "resources/templates/list": "resourceTemplates"}[method]
            return {key: [], **({"resultType": "complete"} if stateless else {})}
        raise RpcError(-32601, f"method {method} is not available through the gateway")

    # ------------------------------------------------------------------ the decision
    def call(self, params: dict, stateless: bool) -> dict:
        name, args = params.get("name", ""), params.get("arguments") or {}
        if name not in self.tools:
            self.audit.log("call_unknown", tool=name, args=args)
            return _error_result(f"Unknown tool {name!r}.")
        info, _raw = self.tools[name]
        c = self.policy.controls

        decision = decide(info, args, self.session, self.policy, self.profile)
        if decision.verdict == "approve":
            decision = self._resolve_approval(info, args, decision, params, stateless)
            if decision.verdict == "input_required":
                return decision.reason   # type: ignore[return-value]  (an InputRequiredResult)

        if decision.verdict == "deny":
            self.audit.log("call_blocked", tool=name, control=decision.control, reason=decision.reason, args=args)
            return _error_result(f"Blocked by gateway ({decision.control}): {decision.reason}.")

        # outbound filter: links and images to foreign hosts never leave in arguments
        if c.outbound_filter and info.effect != "none":
            args, n = strip_foreign_links(args, self.policy.egress_allow)
            if n:
                self.audit.log("outbound_filtered", tool=name, removed=n)

        try:
            result = self.upstreams[info.server].request("tools/call", {"name": info.name, "arguments": args})
        except KeyError:
            self.audit.log("call_failed", tool=name, reason="server not running")
            return _error_result(f"Server {info.server!r} is not running.")
        except RpcError as e:
            # The server spoke: its error text reaches the model like a result, so it taints like one.
            record(info, self.session)
            self.audit.log("call_failed", tool=name, reason=str(e)[:200])
            return self._filter_result(info, _error_result(f"Upstream error: {e.message}"))
        record(info, self.session)
        self.audit.log("call_allowed", tool=name, control=decision.control or "", args=args,
                       owner_reply=is_owner_reply(info, args, self.policy.owner),
                       session_labels="".join(sorted(self.session.labels)))
        return self._filter_result(info, result)

    def _resolve_approval(self, info: ToolInfo, args: dict, d: Decision, params: dict, stateless: bool):
        mode = self.policy.controls.approval
        if mode == "stamp":
            self.audit.log("approval_stamped", tool=info.qualified, control=d.control, reason=d.reason)
            return Decision("allow", d.control, "approved without review")
        if mode == "deny" or not self.client_can_elicit:
            return Decision("deny", d.control, d.reason + " (needs human approval; none available)")

        form = approval.form(info.qualified, args, d.reason, recipient_fields(info.recipient_args, info.arg_names))
        if stateless:   # 2026-07-28: multi round-trip request
            responses, state = params.get("inputResponses"), params.get("requestState")
            if responses is None or state is None:
                self.audit.log("approval_requested", tool=info.qualified, control=d.control, mode="mrtr")
                return Decision("input_required", d.control, {   # type: ignore[arg-type]
                    "resultType": "input_required",
                    "inputRequests": {approval.APPROVAL_KEY: {"method": "elicitation/create", "params": form}},
                    "requestState": self.signer.issue(info.qualified, args),
                })
            ok, why = self.signer.redeem(state, info.qualified, args)
            answer = responses.get(approval.APPROVAL_KEY) if ok else None
        else:           # 2025-11-25: server-initiated elicitation
            self.audit.log("approval_requested", tool=info.qualified, control=d.control, mode="elicitation")
            answer, why = self._ask_client("elicitation/create", form), ""
        if approval.approved(answer):
            self.audit.log("approval_granted", tool=info.qualified, control=d.control)
            return Decision("allow", d.control, "approved by user")
        return Decision("deny", d.control, d.reason + (f" ({why})" if why else " (user declined)"))

    def _filter_result(self, info: ToolInfo, result: dict) -> dict:
        """Clean and filter every string the client may show the model: text items,
        embedded resources and structuredContent alike."""
        c = self.policy.controls
        untrusted = "U" in info.labels
        removed: list[str] = []
        filtered = 0

        def scrub(v):
            nonlocal filtered
            if isinstance(v, str):
                if c.sanitise and untrusted:
                    v, r = clean(v)
                    removed.extend(r)
                if c.outbound_filter:
                    v, n = strip_foreign_links(v, self.policy.egress_allow)
                    filtered += n
                return v
            if isinstance(v, list):
                return [scrub(x) for x in v]
            if isinstance(v, dict):
                return {k: scrub(x) for k, x in v.items()}
            return v

        out = []
        for item in result.get("content", []):
            if item.get("type") == "text":
                text = scrub(item["text"])
                if c.sanitise and untrusted:
                    text = mark_untrusted(text, info.qualified)
                item = {**item, "text": text}
            else:
                item = scrub(item)
            out.append(item)
        cleaned = {**result, "content": out}
        if "structuredContent" in result:
            cleaned["structuredContent"] = scrub(result["structuredContent"])
        if removed:
            self.audit.log("result_cleaned", tool=info.qualified, removed=removed)
        if filtered:
            self.audit.log("result_filtered", tool=info.qualified, removed=filtered)
        return cleaned


def _error_result(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": True}
