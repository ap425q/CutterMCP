[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://www.linkedin.com/in/amey-pathak/)

![cutter_MCP_logo](images/cutterMCP.png)


# cutterMCP
cutterMCP is an Model Context Protocol server for allowing LLMs to autonomously reverse engineer applications. It exposes numerous tools from core Ghidra functionality to MCP clients.

# Features
MCP Server + Cutter Plugin

- Decompile and analyze binaries in Cutter
- Automatically rename methods and data
- List methods, imports, and exports

# Installation

## Prerequisites
- Install [Cutter](https://github.com/rizinorg/cutter)
- Python3
- MCP [SDK](https://github.com/modelcontextprotocol/python-sdk)

## Cutter
First, download the latest release from this repository. This contains the Cutter plugin and Python MCP client. Then, you can directly import the plugin into Cutter.

1. Run Cutter
2. Go to **Edit -> Preferences -> Plugins**
3. Find the plugin directory location
4. Copy `GhidraMCPPlugin.py` from the downloaded release and paste it inside the **python** folder
5. Restart Cutter
6. If successful, you’ll see the plugin under **Windows -> Plugins** and a new widget in the bottom panel


## MCP Clients

Theoretically, any MCP client should work with cutterMCP. one example is given below.

## Example 1: Claude Desktop
To set up Claude Desktop as a Cutter MCP client, go to `Claude` -> `Settings` -> `Developer` -> `Edit Config` -> `claude_desktop_config.json` and add the following:

MacOS/Linux :
```json
{
  "mcpServers": {
    "cutter": {
      "command": "python",
      "args": [
        "/ABSOLUTE_PATH_TO/bridge_mcp_cutter.py"
      ]
    }
  }
}
```

Windows :
```json
{
  "mcpServers": {
    "cutter": {
      "command": "python",
      "args": [
        "C:\\ABSOLUTE_PATH_TO\\bridge_mcp_cutter.py"
      ]
    }
  }
}
```