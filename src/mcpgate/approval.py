"""Asking a human, in both protocol generations.

2025-11-25 and earlier: the gateway sends ``elicitation/create`` to the client
and waits for the answer.

2026-07-28 (multi round-trip requests, SEP-2322): the gateway answers the call
with ``resultType: "input_required"``; the client asks the user and retries the
same call with ``inputResponses`` and the ``requestState`` it was given. The spec
says servers must treat requestState as attacker-controlled, so the gateway signs
it and binds it to the exact call, an expiry and a single-use nonce.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

from .sanitize import destinations

APPROVAL_KEY = "mcpgate_approval"
_TTL = 300


def form(tool: str, args: dict, reason: str, recipient_args: list[str] = ()) -> dict:
    # Recipients and hosts come first and are never cut off: the model chooses the
    # order and length of the arguments, and could push the destination out of view.
    sends_to = "; ".join(f"{a}: {str(args[a])[:200]}" for a in recipient_args if args.get(a))
    hosts = sorted(set(destinations(args)))
    shown = json.dumps(args, ensure_ascii=False)
    lines = [f"An agent wants to call {tool}."]
    if sends_to:
        lines.append(f"Sends to: {sends_to}")
    lines.append("Hosts named in the arguments: " + (", ".join(hosts[:20]) + (f" and {len(hosts) - 20} more" if len(hosts) > 20 else "")
                                                     if hosts else "none"))
    lines.append("Arguments: " + (shown if len(shown) <= 600 else shown[:600] + " [...]"))
    return {
        "mode": "form",
        "message": "\n".join(lines) + f"\nWhy you are asked: {reason}.\nApprove this one call?",
        "requestedSchema": {
            "type": "object",
            "properties": {"approve": {"type": "boolean", "title": "Approve this call"}},
            "required": ["approve"],
        },
    }


def approved(elicit_result: dict | None) -> bool:
    return bool(elicit_result and elicit_result.get("action") == "accept"
                and (elicit_result.get("content") or {}).get("approve") is True)


def _digest(tool: str, args: dict) -> str:
    return hashlib.sha256(json.dumps([tool, args], sort_keys=True).encode()).hexdigest()


class StateSigner:
    def __init__(self) -> None:
        self._key = secrets.token_bytes(32)
        self._used: set[str] = set()

    def issue(self, tool: str, args: dict) -> str:
        body = json.dumps({"d": _digest(tool, args), "exp": int(time.time()) + _TTL,
                           "n": secrets.token_hex(8)}, separators=(",", ":")).encode()
        sig = hmac.new(self._key, body, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(body).decode() + "." + base64.urlsafe_b64encode(sig).decode()

    def redeem(self, state: str, tool: str, args: dict) -> tuple[bool, str]:
        try:
            b64body, b64sig = state.split(".", 1)
            body = base64.urlsafe_b64decode(b64body)
            sig = base64.urlsafe_b64decode(b64sig)
        except Exception:
            return False, "malformed requestState"
        if not hmac.compare_digest(sig, hmac.new(self._key, body, hashlib.sha256).digest()):
            return False, "requestState signature invalid"
        data = json.loads(body)
        if data["exp"] < time.time():
            return False, "approval expired"
        if data["d"] != _digest(tool, args):
            return False, "approval was for a different call"
        if data["n"] in self._used:
            return False, "approval already used"
        self._used.add(data["n"])
        return True, ""
