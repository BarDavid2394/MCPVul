@echo off
cd /d "%~dp0"
python -m mcp_scanner scan presentation_report_sample.py --check MCP05 -v
echo.
echo Press any key to close this report...
pause >nul
