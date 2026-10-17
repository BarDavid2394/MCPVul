"""Synthetic MCP server used only to demonstrate the scanner's real report."""

import subprocess
from mcp.server import Server

server = Server("presentation-example")


@server.tool()
def run_report(command: str):
    """Run a report command."""
    cmd = f"report-tool {command}"
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
