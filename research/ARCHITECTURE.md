# Frida Architecture Analysis

## Overview

Frida is a dynamic instrumentation toolkit that allows developers to inject snippets of JavaScript (or shared libraries) into native apps on Windows, macOS, Linux, iOS, Android, and QNX. It uses a client-server architecture where the client (Python, Node.js, CLI tools) communicates with a core engine (`frida-core`) which manages sessions and injects the `frida-agent` into the target process. The agent uses `frida-gum` to perform the actual instrumentation.

## Directory Structure (`subprojects/`)

*   **`frida-core`**: The central component. Written in Vala. Handles:
    *   Process injection.
    *   Device management (Local, USB, Remote/TCP).
    *   Session life-cycle (Spawn, Attach, Detach).
    *   Communication channels (DBus-based).
*   **`frida-gum`**: The instrumentation engine. Written in C. Handles:
    *   `GumInterceptor`: Function hooking.
    *   `GumStalker`: Instruction-level tracing.
    *   `GumMemory`: Memory scanning and manipulation.
    *   `gumjs`: JavaScript runtime bindings (V8/QuickJS) for Gum.
*   **`frida-python`**: Python bindings for `frida-core`.
    *   Uses C-extensions to wrap the Vala/C core.
    *   Exposes the `frida` module.
*   **`frida-tools`**: CLI tools implemented in Python.
    *   `frida`, `frida-trace`, `frida-ps`, `frida-ls-devices`, etc.
    *   Built on top of `frida-python`.

## Key Modules & Purposes

### 1. Device Manager & Device (`frida-core`)
*   **Purpose**: Discovers and manages connections to targets.
*   **Key Classes**: `DeviceManager`, `Device`.
*   **Functionality**:
    *   Enumerate devices (Local, USB, Remote).
    *   `spawn(program)`: Launches a new process suspended.
    *   `attach(pid)`: Connects to a running process.
    *   `enable_spawn_gating()`: Catches processes as they spawn.

### 2. Session (`frida-core`)
*   **Purpose**: Represents an active connection to a target process.
*   **Key Class**: `Session`.
*   **Functionality**:
    *   `create_script(source)`: Injects JS code.
    *   `enable_child_gating()`: Automatically instrument child processes.
    *   `detach()`: Cleanly disconnects.

### 3. Script (`frida-core` / `frida-gum`)
*   **Purpose**: The unit of instrumentation logic.
*   **Key Class**: `Script`.
*   **Functionality**:
    *   `load()`: Executes the JS payload.
    *   `post(message)`: Sends JSON message to the JS side.
    *   **Signals**: Emits `message` when JS calls `send()`.

### 4. Instrumentation Engine (`frida-gum`)
*   **Purpose**: Low-level manipulation.
*   **Key Components**:
    *   `Interceptor`: `Interceptor.attach(ptr, { onEnter, onLeave })`.
    *   `Stalker`: `Stalker.follow(threadId, { events: ... })`.
    *   `Memory`: `Memory.scan()`, `Memory.protect()`.

## CLI Tool Implementation (`frida-tools`)

The CLI tools are standard Python scripts that inherit from `frida_tools.application.ConsoleApplication`.

**Pattern:**
1.  **Initialization**: `ConsoleApplication` parses arguments (`-U`, `-f`, etc.) and initializes the `Device`.
2.  **Target Acquisition**: Calls `self._device.get_process(pid)` or `spawn()`.
3.  **Session Creation**: Calls `self._device.attach(pid)`.
4.  **Script Injection**:
    *   Reads JS source (or generates it, e.g., `frida-trace`).
    *   Calls `session.create_script(source)`.
    *   Sets up message handlers: `script.on('message', on_message)`.
    *   Calls `script.load()`.
5.  **Event Loop**: Enters a reactor loop to handle signals and messages.

**Example: `frida-ps`**
*   Located in `frida_tools/ps.py`.
*   Uses `device.enumerate_processes()` or `device.enumerate_applications()`.
*   Formats output as Text or JSON.

## RPC & Messaging Patterns

Frida uses a bidirectional message passing system between the Host (Python) and the Agent (JS).

### Host to Agent
*   **Method**: `script.post(message_dict, data_bytes)`
*   **JS Handler**: `recv(type, callback)`

### Agent to Host
*   **Method**: `send(message_dict, data_bytes)`
*   **Python Handler**: `def on_message(message, data): ...`
*   **Message Format**:
    ```json
    {
      "type": "send",
      "payload": { "custom": "data" }
    }
    ```
    (Or `type: "error"` for exceptions).

### RPC (Remote Procedure Call)
Frida supports calling JS functions from Python via `frida.script.exports`.
*   **JS**: `rpc.exports = { myFunction: function(a) { return a * 2; } };`
*   **Python**: `res = script.exports.my_function(5)`

## Programmatic Control (for MCP)

To build an MCP server, we should use the `frida` Python package.

### Recommended Pattern for MCP Tool

```python
import frida
import time
import threading

class FridaTool:
    def __init__(self, device_id=None):
        self.device = frida.get_device(device_id) if device_id else frida.get_local_device()
        self.session = None
        self.script = None
        self.events = []

    def attach(self, target):
        """Target can be PID (int) or Name (str)"""
        self.session = self.device.attach(target)

    def inject_script(self, js_code):
        self.script = self.session.create_script(js_code)
        self.script.on('message', self._on_message)
        self.script.load()

    def _on_message(self, message, data):
        if message['type'] == 'send':
            self.events.append(message['payload'])
        elif message['type'] == 'error':
            print(f"Error: {message['description']}")

    def rpc_call(self, method, *args):
        """Call a function exported in the JS script"""
        return getattr(self.script.exports, method)(*args)

    def cleanup(self):
        if self.script:
            self.script.unload()
        if self.session:
            self.session.detach()

# Example Usage
# tool = FridaTool()
# tool.attach("Twitter")
# tool.inject_script("rpc.exports = { getPid: () => Process.id };")
# print(tool.rpc_call("getPid"))
```

### Critical Capabilities for MCP
1.  **Device Listing**: `frida.enumerate_devices()` to let user pick target.
2.  **Process Listing**: `device.enumerate_processes()` to find target.
3.  **Ad-hoc Instrumentation**: Allow user to supply JS code (Interceptor hooks).
4.  **Tracing**: Generate `frida-trace` style scripts dynamically for specific functions.
