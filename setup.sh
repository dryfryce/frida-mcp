#!/bin/bash
echo "Installing Frida MCP dependencies..."
pip3 install --break-system-packages frida frida-tools mcp

echo "Setup complete. Run with: python3 server.py"
