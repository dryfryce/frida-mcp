# Frida MCP Tools Specification

This document defines the tools and capabilities of the Frida Dynamic Instrumentation Toolkit that should be exposed via an MCP (Model Context Protocol) server.

## 1. Frida CLI Tools

These tools are installed via `pip install frida-tools`.

### `frida` (The REPL)
- **Description**: The interactive Python-based REPL for Frida. Allows connecting to processes and executing JavaScript instrumentation scripts interactively.
- **Parameters**:
  - `target`: Process ID or Process Name to attach to.
  - `-U` / `--usb`: Connect to USB device.
  - `-R` / `--remote`: Connect to remote device.
  - `-l SCRIPT`: Load a script (file).
  - `--debug`: Enable Node.js compatible debugger.
- **Return Value**: Interactive Session (Text output).
- **Example**: `frida -U -l my-hook.js com.example.app`

### `frida-ps`
- **Description**: List processes on a device.
- **Parameters**:
  - `-U` / `--usb`: List on USB device.
  - `-R` / `--remote`: List on remote device.
  - `-D ID`: Connect to device with ID.
  - `-a` / `--applications`: List only applications (installed apps).
  - `-i`: Include installed applications (even if not running).
- **Return Value**: Table of [PID, Name, Identifier].
- **Example**: `frida-ps -Uai` (List all installed apps on USB device)

### `frida-trace`
- **Description**: Dynamically trace function calls matching a pattern.
- **Parameters**:
  - `target`: Process ID or Name.
  - `-i PATTERN`: Include functions matching glob pattern (e.g. `open*`).
  - `-x PATTERN`: Exclude functions.
  - `-I MODULE`: Include all functions in module.
  - `-U`: USB device.
  - `-j CLASS!METHOD`: Trace Java methods (Android).
  - `-m CLASS/METHOD`: Trace ObjC methods (iOS/macOS).
- **Return Value**: Logs of function calls to stdout, creates handler scripts in `__handlers__/`.
- **Example**: `frida-trace -U -i "open*" com.apple.AppStore`

### `frida-ls-devices`
- **Description**: List available devices.
- **Parameters**: None (standard connection flags apply).
- **Return Value**: List of devices [Id, Type, Name].
- **Example**: `frida-ls-devices`

### `frida-kill`
- **Description**: Kill a process.
- **Parameters**:
  - `target`: PID or Name.
  - `-D`: Device ID.
- **Return Value**: Status code.
- **Example**: `frida-kill -U com.malware.app`

### `frida-discover`
- **Description**: Discover internal functions and memory regions in a process (code coverage/discovery tool).
- **Parameters**: `target` process.
- **Return Value**: Interactive UI showing threads and modules.
- **Example**: `frida-discover -U -p 1234`

### `frida-compile`
- **Description**: Compile a Frida agent (modern JavaScript/TypeScript) into a single JS file.
- **Parameters**:
  - `entrypoint`: The .js or .ts file.
  - `-o OUTPUT`: Output filename.
  - `-w`: Watch mode.
- **Return Value**: Compiled JS Bundle.
- **Example**: `frida-compile agent.ts -o _agent.js`

### `frida-create`
- **Description**: Create a new Frida agent project (scaffolding).
- **Parameters**: `name` of the agent/project.
- **Return Value**: New directory with boilerplate.
- **Example**: `frida-create my-agent`

### `frida-apk`
- **Description**: Manipulate Android APKs (e.g., list contents, inspect).
- **Parameters**: `apk_file`.
- **Return Value**: APK Info.
- **Example**: `frida-apk list my-app.apk`

### `frida-push` / `frida-pull`
- **Description**: Copy files to/from a device.
- **Parameters**: `local_path`, `remote_path`.
- **Example**: `frida-push -U agent.js /data/local/tmp/`

## 2. Frida Python API

The `frida` Python package exposes the core instrumentation engine.

### Core Module (`frida`)
These are top-level functions.

| Function | Parameters | Description |
| :--- | :--- | :--- |
| `attach(target)` | `target` (int/str) | Attach to a running process. Returns `Session`. |
| `spawn(program)` | `program` (path/argv) | Spawn a new process. Returns `pid`. |
| `resume(pid)` | `pid` (int) | Resume a spawned process. |
| `kill(pid)` | `pid` (int) | Kill a process. |
| `get_usb_device(timeout)` | `timeout` (int) | Get the connected USB device. Returns `Device`. |
| `get_remote_device()` | None | Get the remote device. Returns `Device`. |
| `get_local_device()` | None | Get the local host device. Returns `Device`. |
| `enumerate_devices()` | None | List all known devices. Returns `List[Device]`. |
| `shutdown()` | None | Shutdown the Frida runtime. |

### Class: `Device`
Represents a physical or virtual device (e.g. Local Machine, Android Phone).

| Method | Parameters | Description |
| :--- | :--- | :--- |
| `attach(target)` | `target` (pid/name) | Attach to process. Returns `Session`. |
| `spawn(program, argv, ...)` | `program` | Spawn process. Returns `pid`. |
| `resume(pid)` | `pid` | Resume process. |
| `kill(pid)` | `pid` | Kill process. |
| `enumerate_processes()` | None | List running processes. Returns `List[Process]`. |
| `enumerate_applications()` | None | List installed apps. Returns `List[Application]`. |
| `get_process(name)` | `name` | Find process by name. |
| `get_frontmost_application()` | None | Get currently visible app. |
| `inject_library_file(...)` | `target`, `path`, `entry`, `data` | Inject .so/.dll into process. |
| `open_channel(address)` | `address` | Open data channel to device. |

### Class: `Session`
Represents an active connection to a process.

| Method | Parameters | Description |
| :--- | :--- | :--- |
| `create_script(source)` | `source` (str) | Compile and create a JS script. Returns `Script`. |
| `create_script_from_bytes(data)`| `data` (bytes) | Create script from bytecode. |
| `detach()` | None | Detach from the process. |
| `enable_child_gating()` | None | Intercept child process spawning. |
| `disable_child_gating()` | None | Disable child gating. |

### Class: `Script`
Represents the injected JavaScript agent.

| Method | Parameters | Description |
| :--- | :--- | :--- |
| `load()` | None | Load/Execute the script in the target. |
| `unload()` | None | Unload the script. |
| `post(message, data)` | `message` (JSON) | Send message to the script. |
| `on(signal, callback)` | `signal` ('message', 'destroyed') | Listen for messages from JS. |
| `exports_sync` | None | Proxy to call RPC exports synchronously. |
| `exports_async` | None | Proxy to call RPC exports asynchronously. |

## 3. Frida JavaScript API

This API is available inside the `create_script("...")` source code.

### Core
- `console.log(msg)`: Print to host console.
- `send(message, [data])`: Send JSON message (and binary data) to Python host.
- `recv(callback)`: Receive message from Python host.

### Process & Memory
- `Process.id`: Current PID.
- `Process.arch`: Architecture ('x64', 'arm64', etc).
- `Process.platform`: OS ('linux', 'darwin', 'windows', 'android').
- `Process.enumerateModules()`: List loaded modules (DLLs/SOs).
- `Process.getModuleByName(name)`: Get module details.
- `Process.enumerateThreads()`: List threads.
- `Memory.scan(address, size, pattern, callbacks)`: Scan memory for byte pattern.
- `Memory.alloc(size)`: Allocate memory.
- `Memory.protect(ptr, size, protection)`: Change page permissions (e.g. 'rwx').
- `Memory.readByteArray(ptr, len)`: Read bytes.
- `Memory.writeByteArray(ptr, bytes)`: Write bytes.

### Instrumentation
- `Interceptor.attach(target, callbacks)`: Hook a native function.
  - `callbacks`: `{ onEnter(args), onLeave(retval) }`
- `Interceptor.replace(target, replacement)`: Replace a native function completely.
- `NativeFunction(address, returnType, argTypes)`: Call a native function.
- `NativeCallback(func, returnType, argTypes)`: Create a C-compatible callback.

### Java (Android)
- `Java.perform(fn)`: Run code in Java VM thread.
- `Java.use(className)`: Get a wrapper for a Java class.
- `Java.choose(className, callbacks)`: Scan heap for instances of a class.
- `Java.cast(handle, klass)`: Cast a handle to a type.
- `Java.scheduleOnMainThread(fn)`: Run on UI thread.

### ObjC (iOS/macOS)
- `ObjC.available`: Check if Objective-C runtime is loaded.
- `ObjC.classes`: Access registered classes.
- `ObjC.choose(class, callbacks)`: Scan heap for instances.
- `new ObjC.Object(ptr)`: Wrap a native pointer as an ObjC object.

### Modules (Stalker, ApiResolver)
- `Stalker.follow([threadId], options)`: Trace execution (instructions/blocks).
- `ApiResolver(type)`: Resolve exports by pattern (e.g. `module:libc.so!open*`).
