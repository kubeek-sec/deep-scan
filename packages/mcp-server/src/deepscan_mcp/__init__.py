"""deepscan-mcp - MCP server exposing the Deep Scan scanner library."""

from .client import upload_project
from .server import main, mcp

__all__ = ["main", "mcp", "upload_project"]
