#!/usr/bin/env python3
"""
Frida MCP Server - Full Frida toolkit exposed via MCP

Provides AI agents with complete access to Frida's dynamic instrumentation capabilities:
- Device discovery and management
- Process listing, spawning, attaching
- Script injection and execution
- Function tracing and discovery
- File operations (pull/push)
- Memory operations
"""

import asyncio
import json
import sys
import os
from typing import Any, Optional
from contextlib import asynccontextmanager

# MCP SDK imports
try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import (
        Tool,
        TextContent,
        CallToolResult,
    )
except ImportError:
    print("Installing mcp package...", file=sys.stderr)
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "mcp"])
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import (
        Tool,
        TextContent,
        CallToolResult,
    )

# Frida import with auto-install
try:
    import frida
except ImportError:
    print("Installing frida package...", file=sys.stderr)
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "frida", "frida-tools"])
    import frida

# Global state
_device_cache: dict[str, frida.core.Device] = {}
_session_cache: dict[str, frida.core.Session] = {}
_script_cache: dict[str, frida.core.Script] = {}

server = Server("frida-mcp")


def get_device(device_id: Optional[str] = None, device_type: str = "local") -> frida.core.Device:
    """Get a Frida device by ID or type."""
    cache_key = device_id or device_type
    
    if cache_key in _device_cache:
        device = _device_cache[cache_key]
        # Check if device is still valid
        try:
            device.query_system_parameters()
            return device
        except:
            del _device_cache[cache_key]
    
    if device_id:
        device = frida.get_device(device_id)
    elif device_type == "usb":
        device = frida.get_usb_device()
    elif device_type == "remote":
        device = frida.get_remote_device()
    else:
        device = frida.get_local_device()
    
    _device_cache[cache_key] = device
    return device


# ============================================
# TOOL DEFINITIONS
# ============================================

TOOLS = [
    # Device Discovery
    Tool(
        name="frida_list_devices",
        description="List all available Frida devices (local, USB, remote). Returns device ID, name, and type.",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": []
        }
    ),
    Tool(
        name="frida_get_device_info",
        description="Get detailed information about a specific device including system parameters.",
        inputSchema={
            "type": "object",
            "properties": {
                "device_id": {"type": "string", "description": "Device ID (optional, defaults to local)"},
                "device_type": {"type": "string", "enum": ["local", "usb", "remote"], "description": "Device type"}
            },
            "required": []
        }
    ),
    
    # Process Management
    Tool(
        name="frida_list_processes",
        description="List all running processes on a device. Returns PID, name, and parameters.",
        inputSchema={
            "type": "object",
            "properties": {
                "device_id": {"type": "string", "description": "Device ID (optional)"},
                "device_type": {"type": "string", "enum": ["local", "usb", "remote"]}
            },
            "required": []
        }
    ),
    Tool(
        name="frida_list_applications",
        description="List all installed applications on a device (useful for mobile devices).",
        inputSchema={
            "type": "object",
            "properties": {
                "device_id": {"type": "string"},
                "device_type": {"type": "string", "enum": ["local", "usb", "remote"]}
            },
            "required": []
        }
    ),
    Tool(
        name="frida_get_process",
        description="Get detailed info about a specific process by name or PID.",
        inputSchema={
            "type": "object",
            "properties": {
                "process": {"type": "string", "description": "Process name or PID"},
                "device_id": {"type": "string"},
                "device_type": {"type": "string", "enum": ["local", "usb", "remote"]}
            },
            "required": ["process"]
        }
    ),
    Tool(
        name="frida_spawn",
        description="Spawn a new process in suspended state. Returns PID. Use frida_resume to start it.",
        inputSchema={
            "type": "object",
            "properties": {
                "program": {"type": "string", "description": "Path to executable or package name"},
                "args": {"type": "array", "items": {"type": "string"}, "description": "Command line arguments"},
                "env": {"type": "object", "description": "Environment variables"},
                "cwd": {"type": "string", "description": "Working directory"},
                "device_id": {"type": "string"},
                "device_type": {"type": "string", "enum": ["local", "usb", "remote"]}
            },
            "required": ["program"]
        }
    ),
    Tool(
        name="frida_resume",
        description="Resume a spawned process.",
        inputSchema={
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "description": "Process ID to resume"},
                "device_id": {"type": "string"},
                "device_type": {"type": "string", "enum": ["local", "usb", "remote"]}
            },
            "required": ["pid"]
        }
    ),
    Tool(
        name="frida_kill",
        description="Kill a process by PID.",
        inputSchema={
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "description": "Process ID to kill"},
                "device_id": {"type": "string"},
                "device_type": {"type": "string", "enum": ["local", "usb", "remote"]}
            },
            "required": ["pid"]
        }
    ),
    
    # Session Management
    Tool(
        name="frida_attach",
        description="Attach to a running process. Returns a session ID for further operations.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Process name or PID"},
                "device_id": {"type": "string"},
                "device_type": {"type": "string", "enum": ["local", "usb", "remote"]}
            },
            "required": ["target"]
        }
    ),
    Tool(
        name="frida_detach",
        description="Detach from a session.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Session ID from frida_attach"}
            },
            "required": ["session_id"]
        }
    ),
    
    # Script Injection
    Tool(
        name="frida_inject_script",
        description="Inject and run a Frida JavaScript script in a process. The script can hook functions, intercept calls, modify behavior, read memory, etc.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Session ID from frida_attach"},
                "script": {"type": "string", "description": "JavaScript code to inject"},
                "on_message": {"type": "boolean", "description": "Whether to capture script messages", "default": True}
            },
            "required": ["session_id", "script"]
        }
    ),
    Tool(
        name="frida_unload_script",
        description="Unload a previously injected script.",
        inputSchema={
            "type": "object",
            "properties": {
                "script_id": {"type": "string", "description": "Script ID from frida_inject_script"}
            },
            "required": ["script_id"]
        }
    ),
    Tool(
        name="frida_rpc_call",
        description="Call an exported RPC function in an injected script.",
        inputSchema={
            "type": "object",
            "properties": {
                "script_id": {"type": "string", "description": "Script ID"},
                "method": {"type": "string", "description": "RPC method name"},
                "args": {"type": "array", "description": "Arguments to pass"}
            },
            "required": ["script_id", "method"]
        }
    ),
    
    # Tracing
    Tool(
        name="frida_trace",
        description="Trace function calls matching a pattern. Returns call logs with arguments and return values.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Process name or PID"},
                "include": {"type": "array", "items": {"type": "string"}, "description": "Function patterns to include (e.g., 'recv*', 'SSL_*')"},
                "exclude": {"type": "array", "items": {"type": "string"}, "description": "Function patterns to exclude"},
                "duration": {"type": "integer", "description": "Trace duration in seconds", "default": 10},
                "device_id": {"type": "string"},
                "device_type": {"type": "string", "enum": ["local", "usb", "remote"]}
            },
            "required": ["target", "include"]
        }
    ),
    
    # Memory Operations
    Tool(
        name="frida_memory_scan",
        description="Scan process memory for a pattern.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "pattern": {"type": "string", "description": "Hex pattern to search (e.g., '48 8b 05 ?? ?? ?? ??')"},
                "protection": {"type": "string", "description": "Memory protection filter (e.g., 'r-x')", "default": "r--"}
            },
            "required": ["session_id", "pattern"]
        }
    ),
    Tool(
        name="frida_memory_read",
        description="Read bytes from a specific memory address.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "address": {"type": "string", "description": "Memory address (hex string like '0x12345678')"},
                "size": {"type": "integer", "description": "Number of bytes to read"}
            },
            "required": ["session_id", "address", "size"]
        }
    ),
    Tool(
        name="frida_memory_write",
        description="Write bytes to a specific memory address.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "address": {"type": "string", "description": "Memory address (hex string)"},
                "data": {"type": "string", "description": "Hex string of bytes to write"}
            },
            "required": ["session_id", "address", "data"]
        }
    ),
    
    # Module/Export Enumeration
    Tool(
        name="frida_list_modules",
        description="List all loaded modules/libraries in a process.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"}
            },
            "required": ["session_id"]
        }
    ),
    Tool(
        name="frida_list_exports",
        description="List all exported functions from a module.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "module": {"type": "string", "description": "Module name"}
            },
            "required": ["session_id", "module"]
        }
    ),
    Tool(
        name="frida_list_imports",
        description="List all imported functions in a module.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "module": {"type": "string", "description": "Module name"}
            },
            "required": ["session_id", "module"]
        }
    ),
    
    # File Operations
    Tool(
        name="frida_pull_file",
        description="Pull/download a file from the device.",
        inputSchema={
            "type": "object",
            "properties": {
                "remote_path": {"type": "string", "description": "Path on device"},
                "local_path": {"type": "string", "description": "Local destination path"},
                "device_id": {"type": "string"},
                "device_type": {"type": "string", "enum": ["local", "usb", "remote"]}
            },
            "required": ["remote_path", "local_path"]
        }
    ),
    Tool(
        name="frida_push_file",
        description="Push/upload a file to the device.",
        inputSchema={
            "type": "object",
            "properties": {
                "local_path": {"type": "string", "description": "Local file path"},
                "remote_path": {"type": "string", "description": "Destination path on device"},
                "device_id": {"type": "string"},
                "device_type": {"type": "string", "enum": ["local", "usb", "remote"]}
            },
            "required": ["local_path", "remote_path"]
        }
    ),
    
    # Hooking Helpers
    Tool(
        name="frida_hook_function",
        description="Hook a specific function to log calls, modify arguments, or change return values.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "module": {"type": "string", "description": "Module name (or null for main executable)"},
                "function": {"type": "string", "description": "Function name or address"},
                "on_enter": {"type": "string", "description": "JavaScript code to run on function entry"},
                "on_leave": {"type": "string", "description": "JavaScript code to run on function exit"}
            },
            "required": ["session_id", "function"]
        }
    ),
    Tool(
        name="frida_intercept_method",
        description="Intercept an Objective-C method (iOS) or Java method (Android).",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "class_name": {"type": "string", "description": "Class name"},
                "method_name": {"type": "string", "description": "Method name"},
                "implementation": {"type": "string", "description": "JavaScript replacement implementation"}
            },
            "required": ["session_id", "class_name", "method_name"]
        }
    ),
    
    # Utility
    Tool(
        name="frida_evaluate",
        description="Evaluate arbitrary JavaScript in the Frida runtime of an attached process.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "code": {"type": "string", "description": "JavaScript code to evaluate"}
            },
            "required": ["session_id", "code"]
        }
    ),
    Tool(
        name="frida_get_frontmost",
        description="Get the frontmost application (mobile devices).",
        inputSchema={
            "type": "object",
            "properties": {
                "device_id": {"type": "string"},
                "device_type": {"type": "string", "enum": ["local", "usb", "remote"]}
            },
            "required": []
        }
    ),
    
    # Advanced: Java (Android)
    Tool(
        name="frida_java_enumerate_classes",
        description="Enumerate all loaded Java classes (Android). Returns class names matching an optional pattern.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "pattern": {"type": "string", "description": "Optional regex pattern to filter classes"}
            },
            "required": ["session_id"]
        }
    ),
    Tool(
        name="frida_java_hook_method",
        description="Hook a Java method (Android). Log calls, modify args/return values.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "class_name": {"type": "string", "description": "Fully qualified class name (e.g., 'com.example.MyClass')"},
                "method_name": {"type": "string", "description": "Method name"},
                "overload": {"type": "array", "items": {"type": "string"}, "description": "Method signature for overloaded methods"},
                "log_args": {"type": "boolean", "default": True},
                "log_return": {"type": "boolean", "default": True},
                "modify_return": {"type": "string", "description": "JavaScript expression for new return value"}
            },
            "required": ["session_id", "class_name", "method_name"]
        }
    ),
    Tool(
        name="frida_java_find_instances",
        description="Find live instances of a Java class on the heap (Android).",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "class_name": {"type": "string", "description": "Fully qualified class name"},
                "limit": {"type": "integer", "default": 10}
            },
            "required": ["session_id", "class_name"]
        }
    ),
    Tool(
        name="frida_java_call_method",
        description="Call a method on a Java class or instance (Android).",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "class_name": {"type": "string"},
                "method_name": {"type": "string"},
                "args": {"type": "array", "description": "Method arguments"},
                "static": {"type": "boolean", "default": True}
            },
            "required": ["session_id", "class_name", "method_name"]
        }
    ),
    
    # Advanced: ObjC (iOS/macOS)
    Tool(
        name="frida_objc_enumerate_classes",
        description="Enumerate all loaded Objective-C classes (iOS/macOS).",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "pattern": {"type": "string", "description": "Optional regex pattern to filter classes"}
            },
            "required": ["session_id"]
        }
    ),
    Tool(
        name="frida_objc_hook_method",
        description="Hook an Objective-C method (iOS/macOS).",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "class_name": {"type": "string"},
                "method_name": {"type": "string", "description": "Method selector (e.g., '-[NSString length]' or just 'length')"},
                "log_args": {"type": "boolean", "default": True},
                "log_return": {"type": "boolean", "default": True}
            },
            "required": ["session_id", "class_name", "method_name"]
        }
    ),
    Tool(
        name="frida_objc_find_instances",
        description="Find live instances of an ObjC class on the heap (iOS/macOS).",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "class_name": {"type": "string"},
                "limit": {"type": "integer", "default": 10}
            },
            "required": ["session_id", "class_name"]
        }
    ),
    
    # Advanced: Stalker (instruction tracing)
    Tool(
        name="frida_stalker_trace",
        description="Trace execution at instruction/block level using Stalker. Very powerful but heavy.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "thread_id": {"type": "integer", "description": "Thread ID to trace (0 for all)"},
                "events": {"type": "array", "items": {"type": "string"}, "description": "Events to capture: 'call', 'ret', 'exec', 'block', 'compile'"},
                "duration": {"type": "integer", "default": 5, "description": "Duration in seconds"}
            },
            "required": ["session_id"]
        }
    ),
    
    # Advanced: ApiResolver
    Tool(
        name="frida_resolve_exports",
        description="Find functions matching a pattern using ApiResolver. Supports wildcards.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "query": {"type": "string", "description": "Query pattern (e.g., 'exports:libc.so!open*', 'exports:*!*SSL*')"},
                "limit": {"type": "integer", "default": 100}
            },
            "required": ["session_id", "query"]
        }
    ),
    
    # Advanced: Library Injection
    Tool(
        name="frida_inject_library",
        description="Inject a shared library (.so/.dll/.dylib) into the target process.",
        inputSchema={
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "description": "Process ID"},
                "library_path": {"type": "string", "description": "Path to library file"},
                "entrypoint": {"type": "string", "description": "Function to call after loading"},
                "data": {"type": "string", "description": "Data to pass to entrypoint"},
                "device_id": {"type": "string"},
                "device_type": {"type": "string", "enum": ["local", "usb", "remote"]}
            },
            "required": ["pid", "library_path", "entrypoint"]
        }
    ),
    
    # Advanced: Spawn Gating
    Tool(
        name="frida_enable_spawn_gating",
        description="Enable spawn gating to intercept new processes before they run.",
        inputSchema={
            "type": "object",
            "properties": {
                "device_id": {"type": "string"},
                "device_type": {"type": "string", "enum": ["local", "usb", "remote"]}
            },
            "required": []
        }
    ),
    Tool(
        name="frida_disable_spawn_gating",
        description="Disable spawn gating.",
        inputSchema={
            "type": "object",
            "properties": {
                "device_id": {"type": "string"},
                "device_type": {"type": "string", "enum": ["local", "usb", "remote"]}
            },
            "required": []
        }
    ),
    Tool(
        name="frida_get_pending_spawn",
        description="Get list of processes waiting in spawn gate.",
        inputSchema={
            "type": "object",
            "properties": {
                "device_id": {"type": "string"},
                "device_type": {"type": "string", "enum": ["local", "usb", "remote"]}
            },
            "required": []
        }
    ),
    
    # Process Info
    Tool(
        name="frida_get_process_info",
        description="Get detailed info about the attached process (arch, platform, threads, etc.).",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"}
            },
            "required": ["session_id"]
        }
    ),
    
    # String Search
    Tool(
        name="frida_search_strings",
        description="Search for strings in process memory.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "pattern": {"type": "string", "description": "String to search for (supports wildcards)"},
                "case_sensitive": {"type": "boolean", "default": True},
                "limit": {"type": "integer", "default": 100}
            },
            "required": ["session_id", "pattern"]
        }
    ),
    
    # Compilation & APK
    Tool(
        name="frida_compile_agent",
        description="Compile a Frida agent (JavaScript/TypeScript) using frida-compile. Useful for complex agents with dependencies.",
        inputSchema={
            "type": "object",
            "properties": {
                "source_code": {"type": "string", "description": "Source code content (TS/JS)"},
                "output_filename": {"type": "string", "description": "Output filename (e.g. 'agent.js')", "default": "agent.js"}
            },
            "required": ["source_code"]
        }
    ),
    Tool(
        name="frida_apk_inspect",
        description="Inspect an Android APK file using frida-apk.",
        inputSchema={
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "Path to APK file"}
            },
            "required": ["apk_path"]
        }
    ),
    
    # NEW: Memory Management
    Tool(
        name="frida_memory_alloc",
        description="Allocate memory in the target process. Returns the address of allocated memory.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "size": {"type": "integer", "description": "Number of bytes to allocate"},
                "protection": {"type": "string", "description": "Memory protection (e.g., 'rwx', 'rw-')", "default": "rw-"}
            },
            "required": ["session_id", "size"]
        }
    ),
    Tool(
        name="frida_memory_protect",
        description="Change memory protection/permissions for a memory region.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "address": {"type": "string", "description": "Memory address (hex string)"},
                "size": {"type": "integer", "description": "Size of region"},
                "protection": {"type": "string", "description": "New protection (e.g., 'rwx', 'r-x')"}
            },
            "required": ["session_id", "address", "size", "protection"]
        }
    ),
    Tool(
        name="frida_enumerate_ranges",
        description="Enumerate memory ranges/maps in the process with their protections.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "protection": {"type": "string", "description": "Filter by protection (e.g., 'r--', 'rwx')", "default": "---"}
            },
            "required": ["session_id"]
        }
    ),
    
    # NEW: Thread Operations
    Tool(
        name="frida_enumerate_threads",
        description="List all threads in the process with their state and context.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"}
            },
            "required": ["session_id"]
        }
    ),
    Tool(
        name="frida_backtrace",
        description="Get stack backtrace for a thread. Useful for debugging and analysis.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "thread_id": {"type": "integer", "description": "Thread ID (0 for current thread)", "default": 0},
                "limit": {"type": "integer", "description": "Max frames to return", "default": 20}
            },
            "required": ["session_id"]
        }
    ),
    
    # NEW: Symbol Resolution
    Tool(
        name="frida_debug_symbol",
        description="Resolve debug symbol information from an address or find address from symbol name.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "address": {"type": "string", "description": "Address to resolve (hex string)"},
                "name": {"type": "string", "description": "Symbol name to find"}
            },
            "required": ["session_id"]
        }
    ),
    Tool(
        name="frida_list_symbols",
        description="List debug symbols from a module.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "module": {"type": "string", "description": "Module name"},
                "filter": {"type": "string", "description": "Filter pattern for symbol names"}
            },
            "required": ["session_id", "module"]
        }
    ),
    
    # NEW: Native Function Calling
    Tool(
        name="frida_native_function",
        description="Call a native function directly by address or name. Specify return type and argument types.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "address": {"type": "string", "description": "Function address (hex) or 'module!name'"},
                "return_type": {"type": "string", "description": "Return type: void, int, pointer, etc.", "default": "void"},
                "arg_types": {"type": "array", "items": {"type": "string"}, "description": "Argument types"},
                "args": {"type": "array", "description": "Argument values"}
            },
            "required": ["session_id", "address"]
        }
    ),
    
    # NEW: CModule (Inline C)
    Tool(
        name="frida_cmodule",
        description="Compile and load inline C code for high-performance hooks. Returns symbols exported by the C code.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "code": {"type": "string", "description": "C source code"},
                "symbols": {"type": "object", "description": "External symbols to link"}
            },
            "required": ["session_id", "code"]
        }
    ),
    
    # NEW: ObjC Method Calling
    Tool(
        name="frida_objc_call_method",
        description="Call an Objective-C method on a class or instance (iOS/macOS).",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "class_name": {"type": "string"},
                "method_name": {"type": "string", "description": "Method selector"},
                "args": {"type": "array", "description": "Method arguments"},
                "instance_handle": {"type": "string", "description": "Instance handle (for instance methods)"},
                "static": {"type": "boolean", "default": True}
            },
            "required": ["session_id", "class_name", "method_name"]
        }
    ),
    
    # NEW: Java Class Loading
    Tool(
        name="frida_java_load_dex",
        description="Load a DEX file dynamically into the Android runtime.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "dex_path": {"type": "string", "description": "Path to DEX file on device"},
                "class_name": {"type": "string", "description": "Class to load from DEX"}
            },
            "required": ["session_id", "dex_path"]
        }
    ),
    
    # NEW: Socket Operations
    Tool(
        name="frida_socket_connect",
        description="Create a socket connection from within the target process.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "host": {"type": "string"},
                "port": {"type": "integer"},
                "type": {"type": "string", "enum": ["tcp", "udp"], "default": "tcp"}
            },
            "required": ["session_id", "host", "port"]
        }
    ),
]


# ============================================
# TOOL HANDLERS
# ============================================

@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        result = await handle_tool(name, arguments)
        return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]
    except Exception as e:
        return [TextContent(type="text", text=json.dumps({"error": str(e), "type": type(e).__name__}))]


async def handle_tool(name: str, args: dict[str, Any]) -> Any:
    """Route tool calls to handlers."""
    
    # Device Discovery
    if name == "frida_list_devices":
        devices = frida.enumerate_devices()
        return [{"id": d.id, "name": d.name, "type": d.type} for d in devices]
    
    elif name == "frida_get_device_info":
        device = get_device(args.get("device_id"), args.get("device_type", "local"))
        params = device.query_system_parameters()
        return {
            "id": device.id,
            "name": device.name,
            "type": device.type,
            "system_parameters": params
        }
    
    # Process Management
    elif name == "frida_list_processes":
        device = get_device(args.get("device_id"), args.get("device_type", "local"))
        processes = device.enumerate_processes()
        return [{"pid": p.pid, "name": p.name, "parameters": dict(p.parameters)} for p in processes]
    
    elif name == "frida_list_applications":
        device = get_device(args.get("device_id"), args.get("device_type", "local"))
        apps = device.enumerate_applications()
        return [{"identifier": a.identifier, "name": a.name, "pid": a.pid, "parameters": dict(a.parameters)} for a in apps]
    
    elif name == "frida_get_process":
        device = get_device(args.get("device_id"), args.get("device_type", "local"))
        target = args["process"]
        try:
            pid = int(target)
            # Find process by PID
            for p in device.enumerate_processes():
                if p.pid == pid:
                    return {"pid": p.pid, "name": p.name, "parameters": dict(p.parameters)}
            raise ValueError(f"Process with PID {pid} not found")
        except ValueError:
            if not str(target).isdigit():
                # Find by name
                process = device.get_process(target)
                return {"pid": process.pid, "name": process.name, "parameters": dict(process.parameters)}
            raise
    
    elif name == "frida_spawn":
        device = get_device(args.get("device_id"), args.get("device_type", "local"))
        pid = device.spawn(
            args["program"],
            argv=args.get("args"),
            envp=args.get("env"),
            cwd=args.get("cwd")
        )
        return {"pid": pid, "status": "spawned_suspended"}
    
    elif name == "frida_resume":
        device = get_device(args.get("device_id"), args.get("device_type", "local"))
        device.resume(args["pid"])
        return {"pid": args["pid"], "status": "resumed"}
    
    elif name == "frida_kill":
        device = get_device(args.get("device_id"), args.get("device_type", "local"))
        device.kill(args["pid"])
        return {"pid": args["pid"], "status": "killed"}
    
    # Session Management
    elif name == "frida_attach":
        device = get_device(args.get("device_id"), args.get("device_type", "local"))
        target = args["target"]
        try:
            target_pid = int(target)
        except ValueError:
            # Find process by name
            process = device.get_process(target)
            target_pid = process.pid
        session = device.attach(target_pid)
        session_id = f"session_{id(session)}"
        _session_cache[session_id] = session
        return {"session_id": session_id, "pid": target_pid}
    
    elif name == "frida_detach":
        session_id = args["session_id"]
        if session_id in _session_cache:
            _session_cache[session_id].detach()
            del _session_cache[session_id]
            return {"status": "detached"}
        return {"error": "Session not found"}
    
    # Script Injection
    elif name == "frida_inject_script":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        script_code = args["script"]
        
        messages = []
        def on_message(message, data):
            messages.append({"message": message, "data": data.hex() if data else None})
        
        script = session.create_script(script_code)
        if args.get("on_message", True):
            script.on("message", on_message)
        script.load()
        
        script_id = f"script_{id(script)}"
        _script_cache[script_id] = {"script": script, "messages": messages}
        
        return {"script_id": script_id, "status": "loaded"}
    
    elif name == "frida_unload_script":
        script_id = args["script_id"]
        if script_id in _script_cache:
            _script_cache[script_id]["script"].unload()
            messages = _script_cache[script_id]["messages"]
            del _script_cache[script_id]
            return {"status": "unloaded", "messages": messages}
        return {"error": "Script not found"}
    
    elif name == "frida_rpc_call":
        script_id = args["script_id"]
        if script_id not in _script_cache:
            raise ValueError(f"Script {script_id} not found")
        
        script = _script_cache[script_id]["script"]
        method = args["method"]
        call_args = args.get("args", [])
        
        result = getattr(script.exports_sync, method)(*call_args)
        return {"result": result}
    
    # Tracing
    elif name == "frida_trace":
        device = get_device(args.get("device_id"), args.get("device_type", "local"))
        target = args["target"]
        include_patterns = args["include"]
        exclude_patterns = args.get("exclude", [])
        duration = args.get("duration", 10)
        
        try:
            target = int(target)
        except ValueError:
            pass
        
        session = device.attach(target)
        
        # Build trace script
        trace_code = """
        var logs = [];
        var patterns = %s;
        var excludes = %s;
        
        patterns.forEach(function(pattern) {
            var matches = Process.enumerateModules();
            matches.forEach(function(mod) {
                mod.enumerateExports().forEach(function(exp) {
                    if (exp.type === 'function') {
                        var name = mod.name + '!' + exp.name;
                        var shouldInclude = false;
                        
                        patterns.forEach(function(p) {
                            if (name.match(new RegExp(p.replace('*', '.*')))) {
                                shouldInclude = true;
                            }
                        });
                        
                        excludes.forEach(function(e) {
                            if (name.match(new RegExp(e.replace('*', '.*')))) {
                                shouldInclude = false;
                            }
                        });
                        
                        if (shouldInclude) {
                            try {
                                Interceptor.attach(exp.address, {
                                    onEnter: function(args) {
                                        logs.push({
                                            type: 'call',
                                            name: name,
                                            timestamp: Date.now()
                                        });
                                    },
                                    onLeave: function(retval) {
                                        logs.push({
                                            type: 'return',
                                            name: name,
                                            timestamp: Date.now()
                                        });
                                    }
                                });
                            } catch(e) {}
                        }
                    }
                });
            });
        });
        
        rpc.exports = {
            getLogs: function() { return logs; }
        };
        """ % (json.dumps(include_patterns), json.dumps(exclude_patterns))
        
        script = session.create_script(trace_code)
        script.load()
        
        # Wait for duration
        await asyncio.sleep(duration)
        
        logs = script.exports_sync.get_logs()
        script.unload()
        session.detach()
        
        return {"traces": logs, "duration": duration}
    
    # Memory Operations
    elif name == "frida_memory_scan":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        pattern = args["pattern"]
        protection = args.get("protection", "r--")
        
        scan_code = """
        rpc.exports = {
            scan: function(pattern, protection) {
                var results = [];
                Process.enumerateRanges(protection).forEach(function(range) {
                    Memory.scan(range.base, range.size, pattern, {
                        onMatch: function(address, size) {
                            results.push({
                                address: address.toString(),
                                size: size
                            });
                        },
                        onError: function(reason) {},
                        onComplete: function() {}
                    });
                });
                return results;
            }
        };
        """
        
        script = session.create_script(scan_code)
        script.load()
        results = script.exports_sync.scan(pattern, protection)
        script.unload()
        
        return {"matches": results}
    
    elif name == "frida_memory_read":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        address = args["address"]
        size = args["size"]
        
        read_code = f"""
        rpc.exports = {{
            doRead: function() {{
                var addr = new NativePointer('{address}');
                return addr.readByteArray({size});
            }}
        }};
        """
        
        script = session.create_script(read_code)
        script.load()
        data = script.exports_sync.do_read()
        script.unload()
        
        return {"address": address, "size": size, "data": data.hex() if data else None}
    
    elif name == "frida_memory_write":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        address = args["address"]
        data = args["data"]
        
        # Convert hex string to bytes
        data_bytes = bytes.fromhex(data.replace(" ", ""))
        
        write_code = f"""
        rpc.exports = {{
            doWrite: function(data) {{
                var addr = new NativePointer('{address}');
                addr.writeByteArray(data);
                return true;
            }}
        }};
        """
        
        script = session.create_script(write_code)
        script.load()
        result = script.exports_sync.do_write(list(data_bytes))
        script.unload()
        
        return {"address": address, "bytes_written": len(data_bytes), "success": result}
    
    # Module/Export Enumeration
    elif name == "frida_list_modules":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        
        list_code = """
        rpc.exports = {
            listModules: function() {
                return Process.enumerateModules().map(function(m) {
                    return {
                        name: m.name,
                        base: m.base.toString(),
                        size: m.size,
                        path: m.path
                    };
                });
            }
        };
        """
        
        script = session.create_script(list_code)
        script.load()
        modules = script.exports_sync.list_modules()
        script.unload()
        
        return {"modules": modules}
    
    elif name == "frida_list_exports":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        module_name = args["module"]
        
        list_code = f"""
        rpc.exports = {{
            listExports: function() {{
                var mod = Process.findModuleByName('{module_name}');
                if (!mod) return [];
                return mod.enumerateExports().map(function(e) {{
                    return {{
                        name: e.name,
                        type: e.type,
                        address: e.address.toString()
                    }};
                }});
            }}
        }};
        """
        
        script = session.create_script(list_code)
        script.load()
        exports = script.exports_sync.list_exports()
        script.unload()
        
        return {"module": module_name, "exports": exports}
    
    elif name == "frida_list_imports":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        module_name = args["module"]
        
        list_code = f"""
        rpc.exports = {{
            listImports: function() {{
                var mod = Process.findModuleByName('{module_name}');
                if (!mod) return [];
                return mod.enumerateImports().map(function(i) {{
                    return {{
                        name: i.name,
                        type: i.type,
                        module: i.module,
                        address: i.address ? i.address.toString() : null
                    }};
                }});
            }}
        }};
        """
        
        script = session.create_script(list_code)
        script.load()
        imports = script.exports_sync.list_imports()
        script.unload()
        
        return {"module": module_name, "imports": imports}
    
    # Hooking Helpers
    elif name == "frida_hook_function":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        module = args.get("module")
        function = args["function"]
        on_enter = args.get("on_enter", "")
        on_leave = args.get("on_leave", "")
        
        if module:
            hook_code = f"""
            var logs = [];
            var mod = Process.findModuleByName('{module}');
            var func = mod.findExportByName('{function}');
            
            Interceptor.attach(func, {{
                onEnter: function(args) {{
                    var log = {{timestamp: Date.now(), type: 'enter'}};
                    {on_enter}
                    logs.push(log);
                    send({{type: 'enter', func: '{function}'}});
                }},
                onLeave: function(retval) {{
                    var log = {{timestamp: Date.now(), type: 'leave'}};
                    {on_leave}
                    logs.push(log);
                    send({{type: 'leave', func: '{function}'}});
                }}
            }});
            
            rpc.exports = {{
                getLogs: function() {{ return logs; }}
            }};
            """
        else:
            hook_code = f"""
            var logs = [];
            var func = Module.findExportByName(null, '{function}');
            
            Interceptor.attach(func, {{
                onEnter: function(args) {{
                    var log = {{timestamp: Date.now(), type: 'enter'}};
                    {on_enter}
                    logs.push(log);
                    send({{type: 'enter', func: '{function}'}});
                }},
                onLeave: function(retval) {{
                    var log = {{timestamp: Date.now(), type: 'leave'}};
                    {on_leave}
                    logs.push(log);
                    send({{type: 'leave', func: '{function}'}});
                }}
            }});
            
            rpc.exports = {{
                getLogs: function() {{ return logs; }}
            }};
            """
        
        messages = []
        def on_message(message, data):
            messages.append(message)
        
        script = session.create_script(hook_code)
        script.on("message", on_message)
        script.load()
        
        script_id = f"hook_{id(script)}"
        _script_cache[script_id] = {"script": script, "messages": messages}
        
        return {"script_id": script_id, "status": "hooked", "function": function}
    
    elif name == "frida_intercept_method":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        class_name = args["class_name"]
        method_name = args["method_name"]
        implementation = args.get("implementation", "")
        
        # This works for both ObjC and Java
        intercept_code = f"""
        if (ObjC.available) {{
            var cls = ObjC.classes['{class_name}'];
            if (cls) {{
                Interceptor.attach(cls['{method_name}'].implementation, {{
                    onEnter: function(args) {{
                        send({{type: 'method_call', class: '{class_name}', method: '{method_name}'}});
                        {implementation}
                    }}
                }});
            }}
        }} else if (Java.available) {{
            Java.perform(function() {{
                var cls = Java.use('{class_name}');
                cls['{method_name}'].implementation = function() {{
                    send({{type: 'method_call', class: '{class_name}', method: '{method_name}'}});
                    {implementation}
                    return this['{method_name}'].apply(this, arguments);
                }};
            }});
        }}
        """
        
        messages = []
        def on_message(message, data):
            messages.append(message)
        
        script = session.create_script(intercept_code)
        script.on("message", on_message)
        script.load()
        
        script_id = f"intercept_{id(script)}"
        _script_cache[script_id] = {"script": script, "messages": messages}
        
        return {"script_id": script_id, "status": "intercepted", "class": class_name, "method": method_name}
    
    # Utility
    elif name == "frida_evaluate":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        code = args["code"]
        
        eval_code = f"""
        rpc.exports = {{
            evaluate: function() {{
                return eval({json.dumps(code)});
            }}
        }};
        """
        
        script = session.create_script(eval_code)
        script.load()
        result = script.exports_sync.evaluate()
        script.unload()
        
        return {"result": result}
    
    elif name == "frida_get_frontmost":
        device = get_device(args.get("device_id"), args.get("device_type", "local"))
        app = device.get_frontmost_application()
        if app:
            return {"identifier": app.identifier, "name": app.name, "pid": app.pid}
        return {"error": "No frontmost application"}
    
    # Java (Android) Tools
    elif name == "frida_java_enumerate_classes":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        pattern = args.get("pattern", "")
        
        enum_code = f"""
        var results = [];
        Java.perform(function() {{
            Java.enumerateLoadedClasses({{
                onMatch: function(className) {{
                    var pattern = '{pattern}';
                    if (!pattern || className.match(new RegExp(pattern))) {{
                        results.push(className);
                    }}
                }},
                onComplete: function() {{}}
            }});
        }});
        rpc.exports = {{
            getResults: function() {{ return results; }}
        }};
        """
        
        script = session.create_script(enum_code)
        script.load()
        await asyncio.sleep(1)  # Give time for enumeration
        classes = script.exports_sync.get_results()
        script.unload()
        
        return {"classes": classes, "count": len(classes)}
    
    elif name == "frida_java_hook_method":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        class_name = args["class_name"]
        method_name = args["method_name"]
        log_args = args.get("log_args", True)
        log_return = args.get("log_return", True)
        modify_return = args.get("modify_return", "")
        overload = args.get("overload", [])
        
        overload_js = f".overload({', '.join(repr(t) for t in overload)})" if overload else ""
        
        hook_code = f"""
        var logs = [];
        Java.perform(function() {{
            var cls = Java.use('{class_name}');
            cls['{method_name}']{overload_js}.implementation = function() {{
                var args = Array.prototype.slice.call(arguments);
                var logEntry = {{timestamp: Date.now(), method: '{class_name}.{method_name}'}};
                
                {f'logEntry.args = args.map(function(a) {{ return String(a); }});' if log_args else ''}
                
                var result = this['{method_name}'].apply(this, arguments);
                
                {f'logEntry.returnValue = String(result);' if log_return else ''}
                {f'result = {modify_return};' if modify_return else ''}
                
                logs.push(logEntry);
                send(logEntry);
                return result;
            }};
        }});
        rpc.exports = {{
            getLogs: function() {{ return logs; }}
        }};
        """
        
        messages = []
        def on_message(message, data):
            messages.append(message)
        
        script = session.create_script(hook_code)
        script.on("message", on_message)
        script.load()
        
        script_id = f"java_hook_{id(script)}"
        _script_cache[script_id] = {"script": script, "messages": messages}
        
        return {"script_id": script_id, "status": "hooked", "class": class_name, "method": method_name}
    
    elif name == "frida_java_find_instances":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        class_name = args["class_name"]
        limit = args.get("limit", 10)
        
        find_code = f"""
        var instances = [];
        Java.perform(function() {{
            Java.choose('{class_name}', {{
                onMatch: function(instance) {{
                    if (instances.length < {limit}) {{
                        instances.push({{
                            handle: instance.$h,
                            className: instance.$className,
                            toString: String(instance)
                        }});
                    }}
                }},
                onComplete: function() {{}}
            }});
        }});
        rpc.exports = {{
            getInstances: function() {{ return instances; }}
        }};
        """
        
        script = session.create_script(find_code)
        script.load()
        await asyncio.sleep(1)
        instances = script.exports_sync.get_instances()
        script.unload()
        
        return {"instances": instances, "count": len(instances)}
    
    elif name == "frida_java_call_method":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        class_name = args["class_name"]
        method_name = args["method_name"]
        call_args = args.get("args", [])
        is_static = args.get("static", True)
        
        args_js = ", ".join(json.dumps(a) for a in call_args)
        
        if is_static:
            call_code = f"""
            var result;
            Java.perform(function() {{
                var cls = Java.use('{class_name}');
                result = cls['{method_name}']({args_js});
            }});
            rpc.exports = {{
                getResult: function() {{ return String(result); }}
            }};
            """
        else:
            call_code = f"""
            var result;
            Java.perform(function() {{
                Java.choose('{class_name}', {{
                    onMatch: function(instance) {{
                        result = instance['{method_name}']({args_js});
                        return 'stop';
                    }},
                    onComplete: function() {{}}
                }});
            }});
            rpc.exports = {{
                getResult: function() {{ return String(result); }}
            }};
            """
        
        script = session.create_script(call_code)
        script.load()
        await asyncio.sleep(0.5)
        result = script.exports_sync.get_result()
        script.unload()
        
        return {"result": result}
    
    # ObjC (iOS/macOS) Tools
    elif name == "frida_objc_enumerate_classes":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        pattern = args.get("pattern", "")
        
        enum_code = f"""
        rpc.exports = {{
            enumerate: function() {{
                if (!ObjC.available) return {{error: 'ObjC not available'}};
                var classes = Object.keys(ObjC.classes);
                var pattern = '{pattern}';
                if (pattern) {{
                    classes = classes.filter(function(c) {{
                        return c.match(new RegExp(pattern));
                    }});
                }}
                return classes;
            }}
        }};
        """
        
        script = session.create_script(enum_code)
        script.load()
        classes = script.exports_sync.enumerate()
        script.unload()
        
        if isinstance(classes, dict) and "error" in classes:
            return classes
        return {"classes": classes, "count": len(classes)}
    
    elif name == "frida_objc_hook_method":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        class_name = args["class_name"]
        method_name = args["method_name"]
        log_args = args.get("log_args", True)
        log_return = args.get("log_return", True)
        
        hook_code = f"""
        var logs = [];
        if (ObjC.available) {{
            var cls = ObjC.classes['{class_name}'];
            if (cls) {{
                var method = cls['{method_name}'];
                if (method) {{
                    Interceptor.attach(method.implementation, {{
                        onEnter: function(args) {{
                            var log = {{timestamp: Date.now(), class: '{class_name}', method: '{method_name}'}};
                            {f'log.self = ObjC.Object(args[0]).toString();' if log_args else ''}
                            logs.push(log);
                            send(log);
                        }},
                        onLeave: function(retval) {{
                            {f'logs[logs.length-1].returnValue = retval.toString();' if log_return else ''}
                        }}
                    }});
                }}
            }}
        }}
        rpc.exports = {{
            getLogs: function() {{ return logs; }}
        }};
        """
        
        messages = []
        def on_message(message, data):
            messages.append(message)
        
        script = session.create_script(hook_code)
        script.on("message", on_message)
        script.load()
        
        script_id = f"objc_hook_{id(script)}"
        _script_cache[script_id] = {"script": script, "messages": messages}
        
        return {"script_id": script_id, "status": "hooked", "class": class_name, "method": method_name}
    
    elif name == "frida_objc_find_instances":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        class_name = args["class_name"]
        limit = args.get("limit", 10)
        
        find_code = f"""
        rpc.exports = {{
            find: function() {{
                if (!ObjC.available) return {{error: 'ObjC not available'}};
                var instances = [];
                ObjC.choose(ObjC.classes['{class_name}'], {{
                    onMatch: function(instance) {{
                        if (instances.length < {limit}) {{
                            instances.push({{
                                handle: instance.handle.toString(),
                                description: instance.toString()
                            }});
                        }}
                    }},
                    onComplete: function() {{}}
                }});
                return instances;
            }}
        }};
        """
        
        script = session.create_script(find_code)
        script.load()
        instances = script.exports_sync.find()
        script.unload()
        
        if isinstance(instances, dict) and "error" in instances:
            return instances
        return {"instances": instances, "count": len(instances)}
    
    # Stalker
    elif name == "frida_stalker_trace":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        thread_id = args.get("thread_id", 0)
        events = args.get("events", ["call", "ret"])
        duration = args.get("duration", 5)
        
        events_js = ", ".join(f"{e}: true" for e in events)
        
        stalk_code = f"""
        var traces = [];
        var threadId = {thread_id};
        
        if (threadId === 0) {{
            threadId = Process.getCurrentThreadId();
        }}
        
        Stalker.follow(threadId, {{
            events: {{ {events_js} }},
            onCallSummary: function(summary) {{
                for (var addr in summary) {{
                    traces.push({{address: addr, count: summary[addr]}});
                }}
            }}
        }});
        
        rpc.exports = {{
            stop: function() {{
                Stalker.unfollow(threadId);
                return traces;
            }},
            getTraces: function() {{
                return traces;
            }}
        }};
        """
        
        script = session.create_script(stalk_code)
        script.load()
        
        await asyncio.sleep(duration)
        
        traces = script.exports_sync.stop()
        script.unload()
        
        return {"traces": traces, "duration": duration, "thread_id": thread_id}
    
    # ApiResolver
    elif name == "frida_resolve_exports":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        query = args["query"]
        limit = args.get("limit", 100)
        
        resolve_code = f"""
        rpc.exports = {{
            resolve: function() {{
                var results = [];
                var resolver = new ApiResolver('module');
                var matches = resolver.enumerateMatches('{query}');
                matches.slice(0, {limit}).forEach(function(m) {{
                    results.push({{
                        name: m.name,
                        address: m.address.toString()
                    }});
                }});
                return results;
            }}
        }};
        """
        
        script = session.create_script(resolve_code)
        script.load()
        results = script.exports_sync.resolve()
        script.unload()
        
        return {"matches": results, "count": len(results)}
    
    # Library Injection
    elif name == "frida_inject_library":
        device = get_device(args.get("device_id"), args.get("device_type", "local"))
        pid = args["pid"]
        library_path = args["library_path"]
        entrypoint = args["entrypoint"]
        data = args.get("data", "")
        
        device.inject_library_file(pid, library_path, entrypoint, data)
        return {"status": "injected", "pid": pid, "library": library_path}
    
    # Spawn Gating
    elif name == "frida_enable_spawn_gating":
        device = get_device(args.get("device_id"), args.get("device_type", "local"))
        device.enable_spawn_gating()
        return {"status": "spawn_gating_enabled"}
    
    elif name == "frida_disable_spawn_gating":
        device = get_device(args.get("device_id"), args.get("device_type", "local"))
        device.disable_spawn_gating()
        return {"status": "spawn_gating_disabled"}
    
    elif name == "frida_get_pending_spawn":
        device = get_device(args.get("device_id"), args.get("device_type", "local"))
        pending = device.enumerate_pending_spawn()
        return {"pending": [{"pid": p.pid, "identifier": p.identifier} for p in pending]}
    
    # Process Info
    elif name == "frida_get_process_info":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        
        info_code = """
        rpc.exports = {
            getInfo: function() {
                return {
                    id: Process.id,
                    arch: Process.arch,
                    platform: Process.platform,
                    pageSize: Process.pageSize,
                    pointerSize: Process.pointerSize,
                    codeSigningPolicy: Process.codeSigningPolicy,
                    isDebuggerAttached: Process.isDebuggerAttached(),
                    threads: Process.enumerateThreads().map(function(t) {
                        return {id: t.id, state: t.state, context: t.context ? 'available' : 'unavailable'};
                    }),
                    mainModule: (function() {
                        var m = Process.enumerateModules()[0];
                        return {name: m.name, base: m.base.toString(), size: m.size, path: m.path};
                    })()
                };
            }
        };
        """
        
        script = session.create_script(info_code)
        script.load()
        info = script.exports_sync.get_info()
        script.unload()
        
        return info
    
    # String Search
    elif name == "frida_search_strings":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        pattern = args["pattern"]
        case_sensitive = args.get("case_sensitive", True)
        limit = args.get("limit", 100)
        
        search_code = f"""
        rpc.exports = {{
            search: function() {{
                var results = [];
                var pattern = '{pattern}';
                var caseSensitive = {str(case_sensitive).lower()};
                
                Process.enumerateRanges('r--').forEach(function(range) {{
                    if (results.length >= {limit}) return;
                    
                    try {{
                        var content = Memory.readUtf8String(range.base, Math.min(range.size, 1024 * 1024));
                        if (content) {{
                            var searchPattern = caseSensitive ? pattern : pattern.toLowerCase();
                            var searchContent = caseSensitive ? content : content.toLowerCase();
                            var idx = searchContent.indexOf(searchPattern);
                            while (idx !== -1 && results.length < {limit}) {{
                                results.push({{
                                    address: range.base.add(idx).toString(),
                                    preview: content.substr(Math.max(0, idx - 20), 100)
                                }});
                                idx = searchContent.indexOf(searchPattern, idx + 1);
                            }}
                        }}
                    }} catch(e) {{}}
                }});
                return results;
            }}
        }};
        """
        
        script = session.create_script(search_code)
        script.load()
        results = script.exports_sync.search()
        script.unload()
        
        return {"matches": results, "count": len(results)}

    # Compilation & APK
    elif name == "frida_compile_agent":
        import tempfile
        import subprocess
        
        source = args["source_code"]
        output_filename = args.get("output_filename", "agent.js")
        
        # Create temp file in current directory to avoid "entrypoint must be inside project root" error
        with tempfile.NamedTemporaryFile(suffix=".ts", mode="w", dir=".", delete=False) as f:
            f.write(source)
            source_path = f.name
            
        try:
            # Use shell=False for security, but ensure executable is found
            process = subprocess.run(
                ["frida-compile", source_path, "-o", output_filename, "-c"],
                capture_output=True,
                text=True
            )
            
            if process.returncode != 0:
                return {"status": "error", "error": process.stderr or process.stdout or "Unknown error", "code": process.returncode}
                
            with open(output_filename, "r") as f:
                compiled_code = f.read()
            return {"status": "compiled", "filename": output_filename, "code_size": len(compiled_code)}
        except Exception as e:
            return {"status": "error", "error": str(e)}
        finally:
            if os.path.exists(source_path):
                os.remove(source_path)

    elif name == "frida_apk_inspect":
        import subprocess
        apk_path = args["apk_path"]
        
        if not os.path.exists(apk_path):
            return {"error": f"File not found: {apk_path}"}
            
        try:
            # Run frida-apk list
            result = subprocess.run(
                ["frida-apk", "list", apk_path],
                check=True,
                capture_output=True,
                text=True
            )
            return {"output": result.stdout}
        except subprocess.CalledProcessError as e:
            return {"status": "error", "error": e.stderr}

    # NEW: Memory Allocation
    elif name == "frida_memory_alloc":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        size = args["size"]
        protection = args.get("protection", "rw-")
        
        alloc_code = f"""
        rpc.exports = {{
            alloc: function() {{
                var mem = Memory.alloc({size});
                Memory.protect(mem, {size}, '{protection}');
                return mem.toString();
            }}
        }};
        """
        
        script = session.create_script(alloc_code)
        script.load()
        address = script.exports_sync.alloc()
        script.unload()
        
        return {"address": address, "size": size, "protection": protection}

    elif name == "frida_memory_protect":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        address = args["address"]
        size = args["size"]
        protection = args["protection"]
        
        protect_code = f"""
        rpc.exports = {{
            protect: function() {{
                return Memory.protect(ptr('{address}'), {size}, '{protection}');
            }}
        }};
        """
        
        script = session.create_script(protect_code)
        script.load()
        result = script.exports_sync.protect()
        script.unload()
        
        return {"address": address, "size": size, "protection": protection, "success": result}

    elif name == "frida_enumerate_ranges":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        protection = args.get("protection", "---")
        
        enum_code = f"""
        rpc.exports = {{
            enumerate: function() {{
                return Process.enumerateRanges('{protection}').map(function(r) {{
                    return {{
                        base: r.base.toString(),
                        size: r.size,
                        protection: r.protection,
                        file: r.file ? r.file.path : null
                    }};
                }});
            }}
        }};
        """
        
        script = session.create_script(enum_code)
        script.load()
        ranges = script.exports_sync.enumerate()
        script.unload()
        
        return {"ranges": ranges, "count": len(ranges)}

    # NEW: Thread Operations
    elif name == "frida_enumerate_threads":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        
        enum_code = """
        rpc.exports = {
            enumerate: function() {
                return Process.enumerateThreads().map(function(t) {
                    return {
                        id: t.id,
                        state: t.state,
                        context: t.context ? {
                            pc: t.context.pc.toString(),
                            sp: t.context.sp.toString()
                        } : null
                    };
                });
            }
        };
        """
        
        script = session.create_script(enum_code)
        script.load()
        threads = script.exports_sync.enumerate()
        script.unload()
        
        return {"threads": threads, "count": len(threads)}

    elif name == "frida_backtrace":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        limit = args.get("limit", 20)
        
        bt_code = f"""
        rpc.exports = {{
            backtrace: function() {{
                var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
                return bt.slice(0, {limit}).map(function(addr) {{
                    var sym = DebugSymbol.fromAddress(addr);
                    return {{
                        address: addr.toString(),
                        module: sym.moduleName,
                        name: sym.name,
                        fileName: sym.fileName,
                        lineNumber: sym.lineNumber
                    }};
                }});
            }}
        }};
        """
        
        script = session.create_script(bt_code)
        script.load()
        frames = script.exports_sync.backtrace()
        script.unload()
        
        return {"frames": frames, "count": len(frames)}

    # NEW: Symbol Resolution
    elif name == "frida_debug_symbol":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        address = args.get("address")
        name = args.get("name")
        
        if address:
            sym_code = f"""
            rpc.exports = {{
                resolve: function() {{
                    var sym = DebugSymbol.fromAddress(ptr('{address}'));
                    return {{
                        address: sym.address.toString(),
                        name: sym.name,
                        moduleName: sym.moduleName,
                        fileName: sym.fileName,
                        lineNumber: sym.lineNumber
                    }};
                }}
            }};
            """
        elif name:
            sym_code = f"""
            rpc.exports = {{
                resolve: function() {{
                    var sym = DebugSymbol.fromName('{name}');
                    return {{
                        address: sym.address.toString(),
                        name: sym.name,
                        moduleName: sym.moduleName,
                        fileName: sym.fileName,
                        lineNumber: sym.lineNumber
                    }};
                }}
            }};
            """
        else:
            return {"error": "Must provide either address or name"}
        
        script = session.create_script(sym_code)
        script.load()
        result = script.exports_sync.resolve()
        script.unload()
        
        return result

    elif name == "frida_list_symbols":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        module = args["module"]
        filter_pattern = args.get("filter", "")
        
        sym_code = f"""
        rpc.exports = {{
            list: function() {{
                var mod = Process.findModuleByName('{module}');
                if (!mod) return [];
                var symbols = mod.enumerateSymbols();
                var filter = '{filter_pattern}';
                if (filter) {{
                    symbols = symbols.filter(function(s) {{
                        return s.name.indexOf(filter) !== -1;
                    }});
                }}
                return symbols.slice(0, 500).map(function(s) {{
                    return {{
                        address: s.address.toString(),
                        name: s.name,
                        type: s.type,
                        section: s.section ? s.section.id : null
                    }};
                }});
            }}
        }};
        """
        
        script = session.create_script(sym_code)
        script.load()
        symbols = script.exports_sync.list()
        script.unload()
        
        return {"symbols": symbols, "count": len(symbols)}

    # NEW: Native Function Calling
    elif name == "frida_native_function":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        address = args["address"]
        return_type = args.get("return_type", "void")
        arg_types = args.get("arg_types", [])
        call_args = args.get("args", [])
        
        arg_types_js = json.dumps(arg_types)
        call_args_js = json.dumps(call_args)
        
        call_code = f"""
        rpc.exports = {{
            doCall: function() {{
                var addr;
                var addrStr = '{address}';
                if (addrStr.indexOf('!') !== -1) {{
                    var parts = addrStr.split('!');
                    var mod = Process.getModuleByName(parts[0]);
                    addr = mod.findExportByName(parts[1]);
                }} else {{
                    addr = new NativePointer(addrStr);
                }}
                
                if (!addr || addr.isNull()) {{
                    return {{error: 'Function not found: ' + addrStr}};
                }}
                
                var argTypes = {arg_types_js};
                var callArgs = {call_args_js};
                var fn = new NativeFunction(addr, '{return_type}', argTypes);
                var result;
                if (callArgs.length === 0) {{
                    result = fn();
                }} else {{
                    result = fn.apply(null, callArgs);
                }}
                return result !== undefined ? result.toString() : null;
            }}
        }};
        """
        
        script = session.create_script(call_code)
        script.load()
        result = script.exports_sync.do_call()
        script.unload()
        
        return {"result": result, "address": address}

    # NEW: CModule
    elif name == "frida_cmodule":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        code = args["code"]
        symbols = args.get("symbols", {})
        
        symbols_js = json.dumps(symbols)
        code_escaped = json.dumps(code)
        
        cm_code = f"""
        rpc.exports = {{
            compile: function() {{
                var cm = new CModule({code_escaped}, {symbols_js});
                var exports = {{}};
                for (var key in cm) {{
                    if (typeof cm[key] === 'object' && cm[key].toString) {{
                        exports[key] = cm[key].toString();
                    }}
                }}
                return exports;
            }}
        }};
        """
        
        script = session.create_script(cm_code)
        script.load()
        exports = script.exports_sync.compile()
        # Note: keeping script loaded so CModule stays active
        
        script_id = f"cmodule_{id(script)}"
        _script_cache[script_id] = {"script": script, "messages": []}
        
        return {"script_id": script_id, "exports": exports}

    # NEW: ObjC Method Calling
    elif name == "frida_objc_call_method":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        class_name = args["class_name"]
        method_name = args["method_name"]
        call_args = args.get("args", [])
        is_static = args.get("static", True)
        instance_handle = args.get("instance_handle")
        
        args_js = json.dumps(call_args)
        
        if is_static and not instance_handle:
            call_code = f"""
            rpc.exports = {{
                call: function() {{
                    if (!ObjC.available) return {{error: 'ObjC not available'}};
                    var cls = ObjC.classes['{class_name}'];
                    if (!cls) return {{error: 'Class not found'}};
                    var args = {args_js};
                    var result = cls['{method_name}'].apply(cls, args);
                    return {{result: result ? result.toString() : null}};
                }}
            }};
            """
        else:
            call_code = f"""
            rpc.exports = {{
                call: function() {{
                    if (!ObjC.available) return {{error: 'ObjC not available'}};
                    var instance = ObjC.Object(ptr('{instance_handle}'));
                    var args = {args_js};
                    var result = instance['{method_name}'].apply(instance, args);
                    return {{result: result ? result.toString() : null}};
                }}
            }};
            """
        
        script = session.create_script(call_code)
        script.load()
        result = script.exports_sync.call()
        script.unload()
        
        return result

    # NEW: Java DEX Loading
    elif name == "frida_java_load_dex":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        dex_path = args["dex_path"]
        class_name = args.get("class_name")
        
        load_code = f"""
        rpc.exports = {{
            load: function() {{
                var result = {{}};
                Java.perform(function() {{
                    var dexPath = '{dex_path}';
                    var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
                    var File = Java.use('java.io.File');
                    var cacheDir = Java.use('android.app.ActivityThread').currentApplication().getCacheDir().getAbsolutePath();
                    
                    var loader = DexClassLoader.$new(dexPath, cacheDir, null, Java.use('java.lang.ClassLoader').getSystemClassLoader());
                    result.loader = loader.toString();
                    
                    var className = '{class_name or ""}';
                    if (className) {{
                        var loadedClass = loader.loadClass(className);
                        result.class = loadedClass.toString();
                    }}
                }});
                return result;
            }}
        }};
        """
        
        script = session.create_script(load_code)
        script.load()
        await asyncio.sleep(0.5)
        result = script.exports_sync.load()
        script.unload()
        
        return result

    # NEW: Socket Operations
    elif name == "frida_socket_connect":
        session_id = args["session_id"]
        if session_id not in _session_cache:
            raise ValueError(f"Session {session_id} not found")
        
        session = _session_cache[session_id]
        host = args["host"]
        port = args["port"]
        sock_type = args.get("type", "tcp")
        
        socket_code = f"""
        rpc.exports = {{
            connect: function() {{
                var socket = Socket.connect({{
                    family: 'ipv4',
                    host: '{host}',
                    port: {port}
                }});
                return {{
                    localAddress: socket.localAddress,
                    peerAddress: socket.peerAddress,
                    fd: socket.fd
                }};
            }}
        }};
        """
        
        script = session.create_script(socket_code)
        script.load()
        result = script.exports_sync.connect()
        script.unload()
        
        return result

    else:
        raise ValueError(f"Unknown tool: {name}")


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
