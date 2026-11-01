"""Pinning: trust what was reviewed, not what is called the same.

A tool's description is executable in practice: the model reads it and acts on
it. So the gateway fingerprints every part of a tool the model can see, and the
command that starts each server, and compares both against a lock file that a
person reviewed. A changed description (rug pull), a new tool, or a changed
start command is quarantined until someone re-locks it.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path

# Everything in a tool definition that reaches the model or drives behaviour.
VISIBLE_FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def tool_fingerprint(tool: dict) -> str:
    visible = {k: tool[k] for k in VISIBLE_FIELDS if k in tool}
    return "sha256:" + hashlib.sha256(_canonical(visible).encode()).hexdigest()


def command_fingerprint(argv: list[str], env: dict[str, str]) -> str:
    return "sha256:" + hashlib.sha256(_canonical({"argv": argv, "env": env}).encode()).hexdigest()


@dataclass
class LockFile:
    servers: dict[str, dict]

    @classmethod
    def load(cls, path: Path) -> "LockFile | None":
        if not path.exists():
            return None
        return cls(json.loads(path.read_text(encoding="utf-8")).get("servers", {}))

    def save(self, path: Path) -> None:
        path.write_text(json.dumps({"version": 1, "servers": self.servers}, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")

    def command_ok(self, server: str, fp: str) -> bool:
        return self.servers.get(server, {}).get("command") == fp

    def tool_status(self, server: str, tool: dict) -> str:
        """'pinned', 'changed' or 'new'."""
        pinned = self.servers.get(server, {}).get("tools", {}).get(tool["name"])
        if pinned is None:
            return "new"
        return "pinned" if pinned == tool_fingerprint(tool) else "changed"


# ---------- review helper: screen descriptions before locking them ----------
# Screening is advice for the reviewer, not a boundary. A careful attacker can
# write a poisoned description that passes every pattern below.
_SCREENS = {
    "hidden-instruction tag": re.compile(r"<\s*(important|system|instructions?|secret)\b", re.I),
    "addresses the model": re.compile(r"\b(?:AI|assistant|model|LLM)\b.{0,40}\b(?:must|should|always|never)\b", re.I),
    "do-not-tell": re.compile(r"\b(?:do not|don't|never) (?:tell|mention|inform|show)\b", re.I),
    "file or secret access": re.compile(r"(?:~/\.ssh|id_rsa|\.env\b|api[_ -]?keys?|credentials|secrets?/)", re.I),
    "other recipients": re.compile(r"\b(?:bcc|cc|copy)\b.{0,40}@", re.I),
    "data in URL": re.compile(r"https?://\S+[?&]\w+=", re.I),
}


def screen_description(tool: dict, other_tool_names: set[str]) -> list[str]:
    text = " ".join(str(tool.get(k, "")) for k in ("title", "description"))
    text += " " + _canonical(tool.get("inputSchema", {}))
    findings = [label for label, rx in _SCREENS.items() if rx.search(text)]
    if any(unicodedata.category(ch) in ("Cf", "Co") for ch in text):
        findings.append("invisible characters")
    mentioned = sorted(n for n in other_tool_names if n != tool.get("name") and re.search(rf"\b{re.escape(n)}\b", text))
    if mentioned:
        findings.append("mentions other tools: " + ", ".join(mentioned))   # shadowing
    if len(tool.get("description", "")) > 1500:
        findings.append("very long description")
    return findings
