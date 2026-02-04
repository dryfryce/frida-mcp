# Frida MCP Server

A comprehensive MCP (Model Context Protocol) server that exposes the full power of Frida's dynamic instrumentation toolkit to AI agents.

## Features

**41 tools** covering all major Frida capabilities:

### Device & Process Management
- `frida_list_devices` - List all available Frida devices
- `frida_get_device_info` - Get detailed device information
- `frida_list_processes` - List running processes
- `frida_list_applications` - List installed applications
- `frida_get_process` - Get process details by name/PID
- `frida_spawn` - Spawn a new process (suspended)
- `frida_resume` - Resume a spawned process
- `frida_kill` - Kill a process

### Session Management
- `frida_attach` - Attach to a running process
- `frida_detach` - Detach from a session

### Script Injection
- `frida_inject_script` - Inject and run JavaScript in a process
- `frida_unload_script` - Unload an injected script
- `frida_rpc_call` - Call RPC functions in scripts
- `frida_evaluate` - Evaluate arbitrary JavaScript

### Function Hooking
- `frida_hook_function` - Hook native functions
- `frida_intercept_method` - Intercept ObjC/Java methods
- `frida_trace` - Trace function calls with patterns

### Memory Operations
- `frida_memory_scan` - Scan memory for patterns
- `frida_memory_read` - Read bytes from memory
- `frida_memory_write` - Write bytes to memory
- `frida_search_strings` - Search for strings in memory

### Module Enumeration
- `frida_list_modules` - List loaded modules
- `frida_list_exports` - List module exports
- `frida_list_imports` - List module imports
- `frida_resolve_exports` - Find functions by pattern (ApiResolver)

### Java (Android)
- `frida_java_enumerate_classes` - List Java classes
- `frida_java_hook_method` - Hook Java methods
- `frida_java_find_instances` - Find class instances on heap
- `frida_java_call_method` - Call Java methods

### Objective-C (iOS/macOS)
- `frida_objc_enumerate_classes` - List ObjC classes
- `frida_objc_hook_method` - Hook ObjC methods
- `frida_objc_find_instances` - Find class instances on heap

### Advanced
- `frida_stalker_trace` - Instruction-level tracing
- `frida_inject_library` - Inject shared libraries
- `frida_enable_spawn_gating` - Intercept new processes
- `frida_disable_spawn_gating` - Disable spawn gating
- `frida_get_pending_spawn` - Get pending spawned processes
- `frida_get_process_info` - Detailed process information

### File Operations
- `frida_pull_file` - Download file from device
- `frida_push_file` - Upload file to device

## Installation

```bash
# Install dependencies
pip3 install frida frida-tools mcp

# Or with --break-system-packages on newer Ubuntu
pip3 install --break-system-packages frida frida-tools mcp
```

## Usage

### As stdio MCP server

```bash
python3 server.py
```

### Example MCP configuration

```json
{
  "mcpServers": {
    "frida": {
      "command": "python3",
      "args": ["/path/to/frida-mcp/server.py"]
    }
  }
}
```

## Example Workflows

### 1. List processes and attach
```
1. Call frida_list_processes to see running processes
2. Call frida_attach with target="processName" or target=1234 (PID)
3. Use the returned session_id for further operations
```

### 2. Hook a function
```
1. frida_attach to the target process
2. frida_hook_function with the session_id, function name, and optional onEnter/onLeave code
3. Observe the script_id and retrieve logs with frida_unload_script when done
```

### 3. Trace SSL/crypto calls
```
1. frida_attach to a network application
2. frida_trace with include=["*SSL*", "*crypto*"] to see all SSL-related calls
```

### 4. Android app analysis
```
1. frida_list_applications on USB device to find the app
2. frida_attach to the app
3. frida_java_enumerate_classes to explore classes
4. frida_java_hook_method to intercept specific methods
5. frida_java_find_instances to find live objects
```

### 5. Memory forensics
```
1. frida_attach to the target process
2. frida_search_strings to find interesting strings
3. frida_memory_read to dump specific memory regions
4. frida_memory_scan for byte patterns
```

## Device Types

- `local` - Local system (default)
- `usb` - USB-connected device (Android/iOS with frida-server)
- `remote` - Remote frida-server over TCP

## Requirements

- Python 3.8+
- Frida 16.0+ (`pip install frida frida-tools`)
- MCP SDK (`pip install mcp`)

For mobile device support:
- Android: Install frida-server on the device
- iOS: Install frida via jailbreak or use frida-gadget

## Security Notes

⚠️ Frida is a powerful tool that can be used for both security research and malicious purposes. Only use on systems you own or have explicit permission to test.

## License

MIT