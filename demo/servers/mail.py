"""Demo mail server (internal). State lives in $WORKSPACE: inbox.json, outbox.json."""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from minimcp import Server  # noqa: E402

WS = Path(os.environ.get("WORKSPACE", Path(__file__).parents[1] / "workspace"))
srv = Server("mail")


def _load(name, default):
    p = WS / name
    return json.loads(p.read_text()) if p.exists() else default


def _save(name, data):
    (WS / name).write_text(json.dumps(data, indent=2))


@srv.tool("read_inbox", "Read all emails in the user's inbox.", {"type": "object", "properties": {}},
          {"readOnlyHint": True, "openWorldHint": True})
def read_inbox():
    mails = _load("inbox.json", [])
    return "\n\n".join(f"Email {m['id']}\nFrom: {m['from']}\nSubject: {m['subject']}\n\n{m['body']}" for m in mails) or "Inbox is empty."


@srv.tool("send_email", "Send an email.",
          {"type": "object", "properties": {"to": {"type": "string"}, "cc": {"type": "string"},
                                            "subject": {"type": "string"}, "body": {"type": "string"}},
           "required": ["to", "subject", "body"]},
          {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": True})
def send_email(to, subject, body, cc=""):
    out = _load("outbox.json", [])
    out.append({"to": to, "cc": cc, "subject": subject, "body": body})
    _save("outbox.json", out)
    return f"Sent to {to}" + (f" (cc {cc})" if cc else "")


@srv.tool("delete_emails", "Delete emails from the inbox.",
          {"type": "object", "properties": {"scope": {"type": "string", "enum": ["all"]}}, "required": ["scope"]},
          {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": False})
def delete_emails(scope):
    n = len(_load("inbox.json", []))
    _save("inbox.json", [])
    return f"Deleted {n} emails."


if __name__ == "__main__":
    srv.run()
