# Frida MCP Server - Agent Guide

A practical guide for AI agents using the Frida MCP Server for dynamic instrumentation and reverse engineering tasks.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Core Concepts](#core-concepts)
3. [Tool Reference](#tool-reference)
4. [Common Patterns](#common-patterns)
5. [Platform-Specific Notes](#platform-specific-notes)
6. [Error Handling](#error-handling)
7. [Security Considerations](#security-considerations)
8. [Example Workflows](#example-workflows)

---

## Quick Start

### The Basic Workflow

Every Frida instrumentation task follows this pattern:

```
1. DISCOVER → List devices/processes
2. ATTACH   → Connect to target process (returns session_id)
3. INJECT   → Run JavaScript in the process
4. OBSERVE  → Collect data from hooks/traces
5. CLEANUP  → Detach and unload scripts
```

### Minimal Example: Hook a Function

```
Step 1: frida_list_processes
        → Find target PID or name

Step 2: frida_attach(target="chrome")
        → Returns: {"session_id": "session_140234567890", "pid": 1234}

Step 3: frida_hook_function(
          session_id="session_140234567890",
          function="open"
        )
        → Function is now hooked, calls are logged

Step 4: frida_unload_script(script_id="hook_140234567891")
        → Retrieve collected logs

Step 5: frida_detach(session_id="session_140234567890")
        → Clean disconnect
```

### Critical Rules for Agents

1. **Always save the `session_id`** - You need it for ALL subsequent operations
2. **Always save `script_id`s** - Required to unload scripts and get logs
3. **Detach when done** - Leave processes in clean state
4. **Check platform first** - Some tools are Android/iOS only
5. **Use patterns for discovery** - Don't guess function names, search for them

---

## Core Concepts

### Sessions

A **session** represents an active connection to a process. You get one from `frida_attach` or after spawning a process.

```
session_id: "session_140234567890"
```

Sessions are **stateful** - the server caches them. You can have multiple sessions to different processes simultaneously.

### Scripts

A **script** is JavaScript code running inside the target process. Scripts can:
- Hook functions (native, Java, ObjC)
- Read/write memory
- Call functions
- Send messages back to the host

```
script_id: "script_140234567891"
```

Scripts stay loaded until you unload them or the process exits.

### Devices

Frida can instrument processes on:
- **local** - Your current machine (default)
- **usb** - USB-connected Android/iOS device
- **remote** - Network-connected frida-server

Always specify `device_type` when working with mobile devices.

### Memory Addresses

Memory addresses are passed as **hex strings**:
```
"0x7fff12345678"
```

Not integers. This prevents precision loss in JSON.

---

## Tool Reference

### Device & Discovery Tools

| Tool | Purpose | Key Parameters |
|------|---------|----------------|
| `frida_list_devices` | List all Frida devices | None |
| `frida_get_device_info` | Get device details + system params | `device_id`, `device_type` |
| `frida_list_processes` | List running processes | `device_type` |
| `frida_list_applications` | List installed apps (mobile) | `device_type` |
| `frida_get_process` | Get specific process info | `process` (name or PID) |
| `frida_get_frontmost` | Get active app (mobile) | `device_type` |

**When to use each:**
- Start with `frida_list_devices` when targeting mobile devices
- Use `frida_list_applications` for mobile apps (includes non-running apps)
- Use `frida_list_processes` for desktop or to find running mobile apps
- Use `frida_get_frontmost` when you need "whatever app the user is looking at"

### Process Control Tools

| Tool | Purpose | Key Parameters |
|------|---------|----------------|
| `frida_spawn` | Start process suspended | `program`, `args`, `env`, `cwd` |
| `frida_resume` | Resume spawned process | `pid` |
| `frida_kill` | Terminate process | `pid` |
| `frida_attach` | Connect to running process | `target` (name/PID) |
| `frida_detach` | Disconnect from process | `session_id` |

**Spawn vs Attach:**
- Use **spawn** when you need to hook initialization code (runs before main())
- Use **attach** when the process is already running
- After spawn, the process is SUSPENDED - you must call resume!

**Spawn workflow:**
```
1. frida_spawn(program="/path/to/app")  → Returns pid
2. frida_attach(target=pid)              → Returns session_id
3. frida_inject_script(...)              → Set up hooks
4. frida_resume(pid=pid)                 → Start execution
```

### Script Injection Tools

| Tool | Purpose | Key Parameters |
|------|---------|----------------|
| `frida_inject_script` | Run JS in process | `session_id`, `script` |
| `frida_unload_script` | Remove injected script | `script_id` |
| `frida_rpc_call` | Call exported JS function | `script_id`, `method`, `args` |
| `frida_evaluate` | Quick JS eval | `session_id`, `code` |

**inject_script vs evaluate:**
- `inject_script` - For persistent hooks, returns script_id, captures messages
- `evaluate` - For one-off queries, immediately returns result, script is unloaded

**RPC Pattern:**
```javascript
// In your injected script:
rpc.exports = {
    getSecrets: function() {
        return Memory.readUtf8String(ptr("0x12345"));
    },
    setFlag: function(value) {
        Memory.writeU32(ptr("0x12345"), value);
        return true;
    }
};
```
Then call with `frida_rpc_call(script_id, method="getSecrets", args=[])`.

### Function Hooking Tools

| Tool | Purpose | Key Parameters |
|------|---------|----------------|
| `frida_hook_function` | Hook native function | `session_id`, `function`, `module`, `on_enter`, `on_leave` |
| `frida_intercept_method` | Hook ObjC/Java method | `session_id`, `class_name`, `method_name`, `implementation` |
| `frida_trace` | Trace function patterns | `target`, `include`, `exclude`, `duration` |

**hook_function:**
- For native C/C++ functions
- `on_enter` and `on_leave` are JavaScript snippets that run in context
- Access args via `args[0]`, `args[1]`, etc.
- Access return value via `retval` in on_leave

**intercept_method:**
- Works for both ObjC (iOS/macOS) and Java (Android)
- Automatically detects which runtime is available

**trace:**
- Best for discovery - shows which functions are called
- Use patterns like `"*SSL*"`, `"open*"`, `"*password*"`
- Returns logs after duration expires

### Memory Tools

| Tool | Purpose | Key Parameters |
|------|---------|----------------|
| `frida_memory_scan` | Search for byte pattern | `session_id`, `pattern`, `protection` |
| `frida_memory_read` | Read bytes at address | `session_id`, `address`, `size` |
| `frida_memory_write` | Write bytes to address | `session_id`, `address`, `data` |
| `frida_search_strings` | Find strings in memory | `session_id`, `pattern` |
| `frida_memory_alloc` | Allocate new memory | `session_id`, `size`, `protection` |
| `frida_memory_protect` | Change page permissions | `session_id`, `address`, `size`, `protection` |
| `frida_enumerate_ranges` | List memory regions | `session_id`, `protection` |

**Pattern format for memory_scan:**
```
"48 8b 05 ?? ?? ?? ??"   ← Wildcards with ??
"90 90 90"                ← Exact bytes
```

**Protection strings:**
```
"r--"  ← Readable
"rw-"  ← Readable + Writable
"r-x"  ← Readable + Executable
"rwx"  ← All permissions
```

### Module Enumeration Tools

| Tool | Purpose | Key Parameters |
|------|---------|----------------|
| `frida_list_modules` | List loaded libraries | `session_id` |
| `frida_list_exports` | List exported functions | `session_id`, `module` |
| `frida_list_imports` | List imported functions | `session_id`, `module` |
| `frida_resolve_exports` | Find by pattern (fast) | `session_id`, `query` |
| `frida_list_symbols` | List debug symbols | `session_id`, `module`, `filter` |
| `frida_debug_symbol` | Resolve address↔name | `session_id`, `address` or `name` |

**resolve_exports query format:**
```
"exports:libc.so!open*"     ← Functions in specific module
"exports:*!*SSL*"           ← SSL functions in any module
"exports:libcrypto*!*"      ← All exports from libcrypto
```

### Java (Android) Tools

| Tool | Purpose | Key Parameters |
|------|---------|----------------|
| `frida_java_enumerate_classes` | List loaded classes | `session_id`, `pattern` |
| `frida_java_hook_method` | Hook Java method | `session_id`, `class_name`, `method_name`, `overload` |
| `frida_java_find_instances` | Find objects on heap | `session_id`, `class_name`, `limit` |
| `frida_java_call_method` | Invoke Java method | `session_id`, `class_name`, `method_name`, `args`, `static` |
| `frida_java_load_dex` | Load DEX dynamically | `session_id`, `dex_path`, `class_name` |

**Overload handling:**
Java methods can be overloaded. Specify signature:
```python
frida_java_hook_method(
    session_id="...",
    class_name="java.lang.String",
    method_name="substring",
    overload=["int", "int"]  # substring(int, int) specifically
)
```

**Common class patterns:**
```
".*Activity"           ← All Activity classes
"com.example.*"        ← All classes in package
".*Crypto.*"           ← Anything crypto-related
".*Password.*|.*Secret.*"  ← Multiple patterns
```

### Objective-C (iOS/macOS) Tools

| Tool | Purpose | Key Parameters |
|------|---------|----------------|
| `frida_objc_enumerate_classes` | List ObjC classes | `session_id`, `pattern` |
| `frida_objc_hook_method` | Hook ObjC method | `session_id`, `class_name`, `method_name` |
| `frida_objc_find_instances` | Find objects on heap | `session_id`, `class_name`, `limit` |
| `frida_objc_call_method` | Invoke ObjC method | `session_id`, `class_name`, `method_name`, `args`, `instance_handle` |

**ObjC method names:**
```
"- initWithFrame:"     ← Instance method
"+ sharedInstance"     ← Class method
"URLSession:didReceiveData:"  ← Delegate method
```

### Thread & Debugging Tools

| Tool | Purpose | Key Parameters |
|------|---------|----------------|
| `frida_enumerate_threads` | List all threads | `session_id` |
| `frida_backtrace` | Get stack trace | `session_id`, `thread_id`, `limit` |
| `frida_get_process_info` | Detailed process info | `session_id` |

### Advanced Tools

| Tool | Purpose | Key Parameters |
|------|---------|----------------|
| `frida_stalker_trace` | Instruction-level tracing | `session_id`, `thread_id`, `events`, `duration` |
| `frida_native_function` | Call native function | `session_id`, `address`, `return_type`, `arg_types`, `args` |
| `frida_cmodule` | Inject inline C code | `session_id`, `code`, `symbols` |
| `frida_inject_library` | Inject .so/.dll | `pid`, `library_path`, `entrypoint` |
| `frida_compile_agent` | Compile TS/JS agent | `source_code`, `output_filename` |

### Spawn Gating Tools

| Tool | Purpose | Key Parameters |
|------|---------|----------------|
| `frida_enable_spawn_gating` | Catch new processes | `device_type` |
| `frida_disable_spawn_gating` | Stop catching | `device_type` |
| `frida_get_pending_spawn` | List caught processes | `device_type` |

Use spawn gating when you need to instrument child processes or catch app launches on mobile.

### File Transfer Tools

| Tool | Purpose | Key Parameters |
|------|---------|----------------|
| `frida_pull_file` | Download from device | `remote_path`, `local_path` |
| `frida_push_file` | Upload to device | `local_path`, `remote_path` |

### Utility Tools

| Tool | Purpose | Key Parameters |
|------|---------|----------------|
| `frida_apk_inspect` | Analyze Android APK | `apk_path` |
| `frida_socket_connect` | Open socket from process | `session_id`, `host`, `port`, `type` |

---

## Common Patterns

### Pattern 1: SSL Pinning Bypass (Android)

```
1. frida_list_applications(device_type="usb")
   → Find app identifier

2. frida_spawn(program="com.example.app", device_type="usb")
   → Get pid

3. frida_attach(target=pid, device_type="usb")
   → Get session_id

4. frida_java_enumerate_classes(session_id, pattern=".*SSL.*|.*TrustManager.*|.*Certificate.*")
   → Find SSL-related classes

5. frida_inject_script(session_id, script="""
   Java.perform(function() {
       var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
       TrustManagerImpl.verifyChain.implementation = function() {
           return arguments[0]; // Return the chain without verification
       };
   });
   """)

6. frida_resume(pid)
```

### Pattern 2: Method Tracing

```
1. frida_attach(target="app_name")
   → session_id

2. frida_trace(target="app_name", include=["*password*", "*login*", "*auth*"], duration=30)
   → Wait 30s, collect all calls to these functions

3. Analyze results to find interesting entry points

4. frida_hook_function(session_id, function="verify_password", 
     on_enter="log.args = [args[0].readUtf8String(), args[1].readUtf8String()]")
   → Hook specific function with detailed logging
```

### Pattern 3: Memory Dumping

```
1. frida_attach(target="target_process")

2. frida_enumerate_ranges(session_id, protection="r--")
   → Get all readable memory regions

3. frida_search_strings(session_id, pattern="SECRET_KEY")
   → Find where secrets are stored

4. frida_memory_read(session_id, address="0x...", size=256)
   → Dump the memory region
```

### Pattern 4: Heap Analysis (Find Live Objects)

```
# Android
frida_java_find_instances(session_id, class_name="com.example.UserSession", limit=10)
→ Find active session objects, examine their fields

# iOS
frida_objc_find_instances(session_id, class_name="NSURLCredential", limit=10)
→ Find stored credentials in memory
```

### Pattern 5: Function Discovery

```
1. frida_list_modules(session_id)
   → Find interesting modules (e.g., libcrypto.so)

2. frida_list_exports(session_id, module="libcrypto.so")
   → Too many results? Use resolve_exports:

3. frida_resolve_exports(session_id, query="exports:libcrypto.so!*encrypt*")
   → Find only encryption-related functions
```

### Pattern 6: Return Value Modification

```
frida_java_hook_method(
    session_id=session_id,
    class_name="com.example.LicenseChecker",
    method_name="isLicenseValid",
    modify_return="true"  # Always return true
)
```

### Pattern 7: Native Function Calling

```
# Call a function directly
frida_native_function(
    session_id=session_id,
    address="libc.so!getpid",
    return_type="int",
    arg_types=[],
    args=[]
)
→ Returns the process ID
```

---

## Platform-Specific Notes

### Android

**Setup:**
- Requires rooted device or emulator
- Run `frida-server` as root on device
- Connect via `device_type="usb"`

**Common Paths:**
```
/data/data/<package>/       ← App private data
/data/app/<package>/        ← APK location
/system/lib64/              ← System libraries
```

**Java-specific:**
- Use `Java.perform()` in scripts for Java operations
- Class names are fully qualified: `com.example.MyClass`
- Inner classes use `$`: `com.example.MyClass$InnerClass`
- Anonymous classes: `com.example.MyClass$1`

**Common bypass targets:**
- Root detection: `com.scottyab.rootbeer`, class names containing "Root"
- SSL pinning: `TrustManager`, `X509TrustManager`, `CertificatePinner`
- Integrity checks: `PackageManager`, signature verification

### iOS

**Setup:**
- Requires jailbroken device (or use frida-gadget for non-jailbroken)
- Frida should be installed via Cydia/Sileo
- Connect via `device_type="usb"`

**Objective-C specifics:**
- Class names don't have packages: `NSURLSession`, `UIViewController`
- Method selectors include colons: `initWithFrame:`, `setObject:forKey:`
- Use `ObjC.classes` in scripts

**Common bypass targets:**
- Jailbreak detection: `fileExistsAtPath:`, check for `/Applications/Cydia.app`
- SSL pinning: `NSURLSession`, `AFNetworking`, `Alamofire`
- Code signing: `SecTrustEvaluate`

### Desktop (Windows/macOS/Linux)

**Setup:**
- No special setup, works with `device_type="local"` (default)
- May need elevated privileges for some processes

**Windows specifics:**
- DLL names: `ntdll.dll`, `kernel32.dll`, `user32.dll`
- Use Windows API names: `CreateFileW`, `ReadFile`

**Linux specifics:**
- Shared libraries: `libc.so.6`, `libssl.so`
- Common targets: `open`, `read`, `write`, `connect`

**macOS specifics:**
- Mix of ObjC and native C
- System Integrity Protection may block some operations
- Use `ObjC.available` to check for ObjC runtime

---

## Error Handling

### Common Errors and Solutions

| Error | Cause | Solution |
|-------|-------|----------|
| `Session not found` | Invalid/expired session_id | Re-attach to the process |
| `Script not found` | Invalid/unloaded script_id | Re-inject the script |
| `Process not found` | Process name doesn't exist | Check exact name with `list_processes` |
| `Failed to attach` | Process protected/permission denied | Try with elevated privileges |
| `Java not available` | Not an Android/JVM process | Use native hooks instead |
| `ObjC not available` | Not an ObjC process | Use native hooks instead |
| `Module not found` | Library not loaded yet | Wait for library load or use spawn |

### Defensive Coding Patterns

**Always check for valid results:**
```
1. Call frida_list_processes
2. Verify target exists before attach
3. Store session_id and verify not null
4. Store script_id after inject
5. Handle possible errors in hooks
```

**Recovery from detached session:**
```
If session error:
1. Check if process still running (frida_list_processes)
2. If running, re-attach
3. Re-inject scripts
```

### Script Errors

Script errors appear in messages with `type: "error"`. Common causes:
- Syntax errors in JavaScript
- Accessing null pointers
- Wrong function signatures
- Race conditions (function not loaded yet)

---

## Security Considerations

### For the Agent

1. **Validate all user inputs** - Don't execute arbitrary code without understanding it
2. **Limit scope** - Only attach to specified processes
3. **Clean up** - Always detach and unload scripts
4. **Avoid production systems** - Frida is for testing/research only

### Legal/Ethical

1. **Own or authorized systems only** - Never instrument software without permission
2. **Research purposes** - Security research, debugging, testing
3. **No malware development** - Don't help create malicious tools
4. **Respect privacy** - Don't exfiltrate user data

### Detection

Be aware that instrumented apps may detect Frida:
- Checking for `frida-server` process
- Scanning for Frida libraries in memory
- Checking for Frida's default port (27042)
- Checking for inline hooks (modified function prologues)

---

## Example Workflows

### Workflow 1: Reverse Engineer an Android App's Authentication

```
Goal: Understand how an app validates user credentials

Step 1: Connect to device
  frida_list_devices()
  → Note the USB device ID

Step 2: Find the app
  frida_list_applications(device_type="usb")
  → Find "com.example.bankapp"

Step 3: Spawn and attach (to catch initialization)
  frida_spawn(program="com.example.bankapp", device_type="usb")
  → pid: 12345
  
  frida_attach(target=12345, device_type="usb")
  → session_id: "session_xxx"

Step 4: Find authentication classes
  frida_java_enumerate_classes(session_id, pattern=".*[Aa]uth.*|.*[Ll]ogin.*")
  → ["com.example.AuthManager", "com.example.LoginActivity", ...]

Step 5: Hook the login method
  frida_java_hook_method(
    session_id,
    class_name="com.example.AuthManager",
    method_name="authenticate",
    log_args=true,
    log_return=true
  )
  → script_id: "java_hook_xxx"

Step 6: Resume the app
  frida_resume(pid=12345)

Step 7: Wait for user to login, then get logs
  frida_unload_script(script_id="java_hook_xxx")
  → Returns logs with credentials and auth result
```

### Workflow 2: Bypass SSL Pinning on iOS

```
Goal: Intercept HTTPS traffic from an iOS app

Step 1: Find and attach to running app
  frida_get_frontmost(device_type="usb")
  → {"identifier": "com.example.app", "pid": 5678}
  
  frida_attach(target=5678, device_type="usb")
  → session_id

Step 2: Find SSL classes
  frida_objc_enumerate_classes(session_id, pattern=".*SSL.*|.*TLS.*|.*Trust.*")

Step 3: Inject pinning bypass
  frida_inject_script(session_id, script="""
  if (ObjC.available) {
    try {
      var SSLSetSessionOption = Module.findExportByName(null, "SSLSetSessionOption");
      Interceptor.replace(SSLSetSessionOption, new NativeCallback(function(context, option, value) {
        return 0; // noErr
      }, 'int', ['pointer', 'int', 'bool']));
      
      var SSLCreateContext = Module.findExportByName(null, "SSLCreateContext");
      Interceptor.replace(SSLCreateContext, new NativeCallback(function(alloc, protocolSide, connectionType) {
        // ... bypass implementation
      }, 'pointer', ['pointer', 'int', 'int']));
      
      console.log("[*] SSL pinning bypassed");
    } catch(e) {
      console.log("[-] Error: " + e);
    }
  }
  """)

Step 4: Use proxy to intercept traffic
  → App's SSL verification is now bypassed
```

### Workflow 3: Find and Dump Encryption Keys

```
Goal: Extract encryption keys from a running process

Step 1: Attach to process
  frida_attach(target="secure_app")
  → session_id

Step 2: Find crypto-related functions
  frida_resolve_exports(session_id, query="exports:*!*crypt*")
  frida_resolve_exports(session_id, query="exports:*!*aes*")
  frida_resolve_exports(session_id, query="exports:*!*key*")

Step 3: Hook key generation/usage
  frida_hook_function(
    session_id,
    function="EVP_EncryptInit_ex",
    module="libcrypto.so",
    on_enter="log.key = args[3].readByteArray(32);"
  )

Step 4: Search memory for known key patterns
  frida_search_strings(session_id, pattern="-----BEGIN")
  → Find PEM-encoded keys
  
  frida_memory_scan(session_id, pattern="30 82", protection="r--")
  → Find DER-encoded certificates/keys

Step 5: Dump found keys
  frida_memory_read(session_id, address="0x...", size=256)
```

### Workflow 4: Trace All Network Activity

```
Goal: See all network connections an app makes

Step 1: Attach
  frida_attach(target="app_name")
  → session_id

Step 2: Trace network functions
  frida_trace(
    target="app_name",
    include=["connect", "send", "recv", "SSL_write", "SSL_read", "*URLSession*"],
    duration=60
  )
  → Wait 60 seconds, collect all network activity

Step 3: For detailed analysis, hook specific functions
  frida_hook_function(
    session_id,
    function="connect",
    on_enter="""
      var sockaddr = args[1];
      var family = sockaddr.readU16();
      if (family === 2) { // AF_INET
        var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
        var ip = sockaddr.add(4).readU8() + '.' + 
                 sockaddr.add(5).readU8() + '.' +
                 sockaddr.add(6).readU8() + '.' +
                 sockaddr.add(7).readU8();
        log.connection = ip + ':' + port;
      }
    """
  )
```

---

## Quick Reference Card

### Essential Tool Sequence

```
frida_list_devices()              → Find device
frida_list_processes()            → Find process  
frida_attach(target)              → Get session_id
frida_inject_script(session_id)   → Get script_id
frida_unload_script(script_id)    → Get logs
frida_detach(session_id)          → Cleanup
```

### Device Types

| Type | Use Case |
|------|----------|
| `local` | Desktop apps, default |
| `usb` | Android/iOS connected via USB |
| `remote` | frida-server on network |

### Memory Protections

| String | Meaning |
|--------|---------|
| `r--` | Read only |
| `rw-` | Read/Write |
| `r-x` | Read/Execute |
| `rwx` | Full access |

### Common Patterns to Trace

| Goal | Pattern |
|------|---------|
| Network | `connect`, `send`, `recv`, `*SSL*`, `*http*` |
| Files | `open`, `read`, `write`, `fopen`, `fread` |
| Crypto | `*crypt*`, `*aes*`, `*rsa*`, `*sha*`, `*key*` |
| Auth | `*password*`, `*login*`, `*auth*`, `*token*` |
| Android | `com.*.Auth*`, `*verify*`, `*license*` |
| iOS | `*Keychain*`, `*Security*`, `*Credential*` |

---

## Appendix: JavaScript API Quick Reference

When writing scripts for `frida_inject_script`, use these APIs:

```javascript
// Logging
console.log("message");
send({type: "data", value: x});  // Send to host

// Memory
ptr("0x12345")                    // Create pointer
Memory.readUtf8String(ptr)        // Read string
Memory.readByteArray(ptr, len)    // Read bytes
Memory.writeUtf8String(ptr, str)  // Write string

// Hooking
Interceptor.attach(ptr, {
  onEnter: function(args) { },
  onLeave: function(retval) { }
});

// Java (Android)
Java.perform(function() {
  var cls = Java.use("com.example.Class");
  cls.method.implementation = function() { };
});

// ObjC (iOS)
ObjC.classes.NSString.stringWithString_("hello");
Interceptor.attach(ObjC.classes.MyClass["- myMethod:"].implementation, ...);

// Process
Process.id                        // PID
Process.arch                      // Architecture
Process.platform                  // OS
Process.enumerateModules()        // List libraries

// Modules
Module.findExportByName(null, "open")  // Find function
Module.findBaseAddress("libc.so")      // Module base
```
