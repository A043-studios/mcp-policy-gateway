"""Demo file server (internal). Reads files below $WORKSPACE only."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from minimcp import Server  # noqa: E402

WS = Path(os.environ.get("WORKSPACE", Path(__file__).parents[1] / "workspace")).resolve()
srv = Server("files")


@srv.tool("read_file", "Read a text file from the shared drive.",
          {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
          {"readOnlyHint": True, "openWorldHint": False})
def read_file(path):
    target = (WS / path).resolve()
    if WS not in target.parents:
        raise ValueError("path outside the shared drive")
    return target.read_text()


if __name__ == "__main__":
    srv.run()
