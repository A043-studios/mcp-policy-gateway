"""Append-only audit log, one JSON object per line.

Arguments are not stored verbatim (they may contain the very data the gateway is
protecting). The log keeps argument names, a hash of the values and every
destination host, which is enough to reconstruct what happened.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

from .sanitize import destinations


class Audit:
    def __init__(self, path: Path | None, echo: bool = False):
        self.path, self.echo = path, echo
        self.events: list[dict] = []

    def log(self, event: str, **fields) -> None:
        if "args" in fields:
            args = fields.pop("args") or {}
            fields["arg_names"] = sorted(args)
            fields["args_sha256"] = hashlib.sha256(json.dumps(args, sort_keys=True).encode()).hexdigest()[:16]
            fields["destinations"] = sorted(set(destinations(args)))
        record = {"ts": round(time.time(), 3), "event": event, **fields}
        self.events.append(record)
        if self.path:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        if self.echo:
            print("[mcpgate] " + json.dumps(record, ensure_ascii=False), file=sys.stderr)
