"""mcpgate: a small policy gateway for the Model Context Protocol.

Companion code to "Who Decides", A+43 Studios Working Paper No. 2026-02.
"""

from .config import Policy
from .gateway import Gateway
from .policy import Decision, Session, ToolInfo, decide, derive

__all__ = ["Policy", "Gateway", "Decision", "Session", "ToolInfo", "decide", "derive"]
__version__ = "1.0.0"
