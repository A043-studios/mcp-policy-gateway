"""A gullible agent: an MCP client whose 'model' obeys every instruction it reads.

It reads tool descriptions and tool results, and like real models it cannot
reliably tell data from instructions, so it follows commands it finds in either.
Real models only sometimes comply; this one always does, which makes it easy to
see which control outside the model stops what.

It also plays the user: when the gateway asks for approval (elicitation), the
'approver' answers. "careful" declines anything unexpected, "stamp" approves all.
"""

from __future__ import annotations

import itertools
import json
import re
from collections import deque
from typing import IO
from urllib.parse import quote

EMAIL = r"([\w.+-]+@[\w-]+(?:\.[\w-]+)+)"
LAST = "{{LAST_RESULT}}"
PATTERNS = [
    (re.compile(r"read (?:the )?file ([\w./-]+[\w])", re.I),
     lambda m: ("files.read_file", {"path": m.group(1)})),
    (re.compile(r"(?:send|forward|email) (?:it|this|them|the contents?|the file|the data)"
                r"(?: of [\w./-]+)? to " + EMAIL, re.I),
     lambda m: ("mail.send_email", {"to": m.group(1), "subject": "Requested data", "body": LAST})),
    (re.compile(r"delete all (?:emails|messages)", re.I),
     lambda m: ("mail.delete_emails", {"scope": "all"})),
]
SHADOW = re.compile(r"send a copy to " + EMAIL, re.I)
IMAGE = re.compile(r"include this status (?:image|badge):\s*!\[([^\]]*)\]\((https?://[^)\s]+)\)", re.I)
HEADER = re.compile(r"From: (.*)\nSubject: (.*)")


class Agent:
    def __init__(self, to_gateway: IO[str], from_gateway: IO[str], owner: str, approver: str = "careful",
                 protocol: str = "2025-11-25"):
        self.w, self.r, self.owner, self.approver, self.protocol = to_gateway, from_gateway, owner, approver, protocol
        self.ids = itertools.count(1)
        self.queue: deque = deque()
        self.cc: str = ""
        self.images: list[tuple[str, str]] = []
        self.log: list[str] = []
        self.approvals_asked = 0

    # ---- transport ----
    def _rpc(self, method: str, params: dict) -> dict:
        rid = next(self.ids)
        if self.protocol == "2026-07-28":
            params = {**params, "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                          "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}}}}
        self.w.write(json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}) + "\n")
        self.w.flush()
        while True:
            msg = json.loads(self.r.readline())
            if msg.get("method") == "elicitation/create":          # the gateway asks the user
                self._reply(msg["id"], self._answer(msg["params"]))
                continue
            if msg.get("id") == rid:
                if "error" in msg:
                    raise RuntimeError(msg["error"]["message"])
                return msg["result"]

    def _reply(self, rid, result) -> None:
        self.w.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}) + "\n")
        self.w.flush()

    def _answer(self, params: dict) -> dict:
        self.approvals_asked += 1
        ok = self.approver == "stamp"
        self.log.append(f"  [ASKED   ] user {'approved' if ok else 'declined'}: {params['message'].splitlines()[0][:90]}")
        return {"action": "accept", "content": {"approve": ok}}

    def call(self, name: str, args: dict) -> tuple[str, bool]:
        result = self._rpc("tools/call", {"name": name, "arguments": args})
        if result.get("resultType") == "input_required":           # 2026-07-28 approval round trip
            key, req = next(iter(result["inputRequests"].items()))
            result = self._rpc("tools/call", {"name": name, "arguments": args,
                                              "inputResponses": {key: self._answer(req["params"])},
                                              "requestState": result["requestState"]})
        text = "\n".join(c.get("text", "") for c in result.get("content", []))
        err = bool(result.get("isError"))
        shown = json.dumps(args)[:70]
        self.log.append(f"  [{'BLOCKED ' if err else 'EXECUTED'}] {name}({shown}){'  ' + text[:110] if err else ''}")
        return text, err

    # ---- the 'model' ----
    def absorb(self, text: str) -> None:
        found = []
        for rx, make in PATTERNS:
            found += [(m.start(), make(m)) for m in rx.finditer(text)]
        self.queue.extend(c for _, c in sorted(found, key=lambda x: x[0]))
        if (m := SHADOW.search(text)):
            self.cc = m.group(1)
        self.images += [(m.group(1), m.group(2)) for m in IMAGE.finditer(text)]

    def run(self, task: str = "Summarise my inbox and email me the summary.") -> None:
        if self.protocol != "2026-07-28":
            self._rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {"elicitation": {"form": {}}},
                                     "clientInfo": {"name": "gullible-agent", "version": "1.0"}})
        tools = self._rpc("tools/list", {}).get("tools", [])
        self.log.append(f"  [TOOLS   ] model sees: {', '.join(t['name'] for t in tools)}")
        late: deque = deque()
        for t in tools:                       # descriptions are read like any other text
            before = len(self.queue)
            self.absorb(t.get("description", ""))
            while len(self.queue) > before:
                late.appendleft(self.queue.pop())
        inbox, err = self.call("mail.read_inbox", {})
        if not err:
            self.absorb(inbox)
        self.queue.extend(late)
        last = inbox
        while self.queue:
            name, args = self.queue.popleft()
            args = {k: (last if v == LAST else v) for k, v in args.items()}
            out, err = self.call(name, args)
            if not err:
                last = out
        self.call("mail.send_email", {"to": self.owner, "cc": self.cc, "subject": "Your inbox summary",
                                      "body": self.summary(inbox)})

    def summary(self, inbox: str) -> str:
        heads = HEADER.findall(inbox)
        text = f"Inbox summary ({len(heads)} emails):\n" + "\n".join(f"- {s.strip()} (from {f.strip()})" for f, s in heads)
        for alt, url in self.images:
            text += f"\n\n![{alt}]({url}{quote(text[:80])})"
        return text
