# Cutter MCP Server using FastMCP

import sys
import requests
import argparse
import logging
from mcp.server.fastmcp import FastMCP

DEFAULT_CUTTER_SERVER = "http://127.0.0.1:8000/"
cutter_server_url = DEFAULT_CUTTER_SERVER

logger = logging.getLogger(__name__)

mcp = FastMCP("cutter-mcp")

def safe_get(endpoint: str, params: dict = None) -> list:
    if params is None:
        params = {}
    url = f"{cutter_server_url}/{endpoint}"
    try:
        response = requests.get(url, params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        if isinstance(data, dict):
            response = requests.post(f"{cutter_server_url}/{endpoint}", data=data, timeout=5)
        else:
            response = requests.post(f"{cutter_server_url}/{endpoint}", data=data.encode("utf-8"), timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_functions(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the binary with their addresses and pagination.
    """
    return safe_get("functions", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile", {"addr": address}))

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the binary.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported symbols in the binary.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

def list_data(offset: int = 0, limit: int = 1000) -> list:
    """
    List defined data for each function with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("renameFunction", {"address": function_address, "newName": new_name})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})



if __name__ == "__main__":
    mcp.run()
