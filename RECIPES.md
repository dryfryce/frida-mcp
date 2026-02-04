# Frida MCP Recipes

Copy-paste ready code snippets for common reverse engineering tasks. Each recipe includes the exact tool calls and JavaScript code needed.

---

## Table of Contents

1. [Setup Recipes](#setup-recipes)
2. [Android Recipes](#android-recipes)
3. [iOS Recipes](#ios-recipes)
4. [Desktop Recipes](#desktop-recipes)
5. [Memory Recipes](#memory-recipes)
6. [Network Recipes](#network-recipes)
7. [Crypto Recipes](#crypto-recipes)
8. [Anti-Detection Bypass](#anti-detection-bypass)

---

## Setup Recipes

### Recipe: Basic Attach Workflow

```
# Step 1: List processes
frida_list_processes()

# Step 2: Attach (by name or PID)
frida_attach(target="target_process")
→ Save session_id

# Step 3: When done
frida_detach(session_id="session_xxx")
```

### Recipe: Spawn and Instrument Early

```
# Spawn suspended (catches initialization code)
frida_spawn(program="/path/to/app")
→ Save pid

# Attach to spawned process
frida_attach(target=<pid>)
→ Save session_id

# Inject hooks BEFORE app runs
frida_inject_script(session_id="session_xxx", script="<your hooks>")
→ Save script_id

# Now let the app run
frida_resume(pid=<pid>)
```

### Recipe: Android App Quick Start

```
# List apps on USB device
frida_list_applications(device_type="usb")

# Spawn app in suspended state
frida_spawn(program="com.example.app", device_type="usb")
→ pid

# Attach
frida_attach(target=<pid>, device_type="usb")
→ session_id

# Setup hooks, then resume
frida_resume(pid=<pid>)
```

### Recipe: iOS App Quick Start

```
# Get frontmost app
frida_get_frontmost(device_type="usb")
→ {"identifier": "...", "pid": 1234}

# Attach to it
frida_attach(target=1234, device_type="usb")
→ session_id
```

---

## Android Recipes

### Recipe: List All Classes in Package

```
frida_java_enumerate_classes(
  session_id="session_xxx",
  pattern="com\\.example\\..*"
)
```

### Recipe: Hook Any Java Method

```javascript
// Use with frida_inject_script
Java.perform(function() {
    var targetClass = Java.use("com.example.TargetClass");
    
    targetClass.targetMethod.implementation = function(arg1, arg2) {
        console.log("Called with: " + arg1 + ", " + arg2);
        var result = this.targetMethod(arg1, arg2);
        console.log("Returned: " + result);
        return result;
    };
});
```

### Recipe: Hook Overloaded Method

```javascript
// Use with frida_inject_script
Java.perform(function() {
    var String = Java.use("java.lang.String");
    
    // Hook specific overload: substring(int beginIndex, int endIndex)
    String.substring.overload("int", "int").implementation = function(start, end) {
        console.log("substring(" + start + ", " + end + ")");
        return this.substring(start, end);
    };
});
```

### Recipe: Find and Call Instance Methods

```javascript
// Use with frida_inject_script
Java.perform(function() {
    Java.choose("com.example.UserManager", {
        onMatch: function(instance) {
            console.log("Found instance: " + instance);
            // Call method on live instance
            var token = instance.getAuthToken();
            console.log("Token: " + token);
        },
        onComplete: function() {}
    });
});
```

### Recipe: Hook All Methods of a Class

```javascript
// Use with frida_inject_script
Java.perform(function() {
    var targetClass = Java.use("com.example.SecureClass");
    var methods = targetClass.class.getDeclaredMethods();
    
    methods.forEach(function(method) {
        var methodName = method.getName();
        var overloads = targetClass[methodName].overloads;
        
        overloads.forEach(function(overload) {
            overload.implementation = function() {
                console.log("Called: " + methodName);
                return this[methodName].apply(this, arguments);
            };
        });
    });
});
```

### Recipe: Bypass Root Detection

```javascript
// Use with frida_inject_script
Java.perform(function() {
    // Common RootBeer bypass
    var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    RootBeer.isRooted.implementation = function() {
        console.log("isRooted() bypassed");
        return false;
    };
    RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() {
        return false;
    };
    
    // File.exists bypass for common root paths
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf("su") !== -1 || 
            path.indexOf("magisk") !== -1 ||
            path.indexOf("supersu") !== -1) {
            console.log("Hiding: " + path);
            return false;
        }
        return this.exists();
    };
});
```

### Recipe: Android SSL Pinning Bypass (Universal)

```javascript
// Use with frida_inject_script
Java.perform(function() {
    // TrustManagerImpl (Android 7+)
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log("[+] Bypassing TrustManagerImpl: " + host);
            return untrustedChain;
        };
    } catch(e) {}
    
    // OkHttp3 CertificatePinner
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCertificates) {
            console.log("[+] Bypassing OkHttp3 pinning: " + hostname);
            return;
        };
    } catch(e) {}
    
    // TrustManager bypass
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var TrustManager = Java.registerClass({
            name: "com.frida.TrustManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
    } catch(e) {}
    
    console.log("[*] SSL Pinning bypass loaded");
});
```

### Recipe: Log All SharedPreferences Access

```javascript
// Use with frida_inject_script
Java.perform(function() {
    var SharedPreferences = Java.use("android.app.SharedPreferencesImpl");
    
    SharedPreferences.getString.implementation = function(key, defValue) {
        var value = this.getString(key, defValue);
        console.log("[SharedPrefs] getString('" + key + "') = " + value);
        return value;
    };
    
    SharedPreferences.getInt.implementation = function(key, defValue) {
        var value = this.getInt(key, defValue);
        console.log("[SharedPrefs] getInt('" + key + "') = " + value);
        return value;
    };
    
    SharedPreferences.getBoolean.implementation = function(key, defValue) {
        var value = this.getBoolean(key, defValue);
        console.log("[SharedPrefs] getBoolean('" + key + "') = " + value);
        return value;
    };
});
```

### Recipe: Intercept HTTP/HTTPS Requests

```javascript
// Use with frida_inject_script  
Java.perform(function() {
    // OkHttp3 Interceptor
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    var Builder = Java.use("okhttp3.OkHttpClient$Builder");
    var Interceptor = Java.use("okhttp3.Interceptor");
    
    var MyInterceptor = Java.registerClass({
        name: "com.frida.LoggingInterceptor",
        implements: [Interceptor],
        methods: {
            intercept: function(chain) {
                var request = chain.request();
                console.log("[HTTP] " + request.method() + " " + request.url().toString());
                var headers = request.headers();
                for (var i = 0; i < headers.size(); i++) {
                    console.log("  " + headers.name(i) + ": " + headers.value(i));
                }
                return chain.proceed(request);
            }
        }
    });
    
    // Hook URL connections
    var URL = Java.use("java.net.URL");
    URL.openConnection.overload().implementation = function() {
        console.log("[URL] " + this.toString());
        return this.openConnection();
    };
});
```

### Recipe: Dump DEX Files

```javascript
// Use with frida_inject_script
Java.perform(function() {
    var DexFile = Java.use("dalvik.system.DexFile");
    var File = Java.use("java.io.File");
    var FileOutputStream = Java.use("java.io.FileOutputStream");
    
    // Hook loadDex to capture dynamically loaded DEX
    var BaseDexClassLoader = Java.use("dalvik.system.BaseDexClassLoader");
    var DexPathList = Java.use("dalvik.system.DexPathList");
    
    DexPathList.makeDexElements.implementation = function(files, optimizedDirectory, suppressedExceptions, classLoader) {
        console.log("[DEX] Loading DEX files:");
        for (var i = 0; i < files.size(); i++) {
            console.log("  " + files.get(i).toString());
        }
        return this.makeDexElements(files, optimizedDirectory, suppressedExceptions, classLoader);
    };
});
```

---

## iOS Recipes

### Recipe: List All Classes in App

```
frida_objc_enumerate_classes(
  session_id="session_xxx",
  pattern="^((?!NS|UI|CF|CA|CG|CI|CT|AV|SCN|SK|MTL).)*$"  // Exclude Apple frameworks
)
```

### Recipe: Hook Objective-C Method

```javascript
// Use with frida_inject_script
if (ObjC.available) {
    var className = "TargetClass";
    var methodName = "- targetMethod:withArg:";
    
    var hook = ObjC.classes[className][methodName];
    Interceptor.attach(hook.implementation, {
        onEnter: function(args) {
            // args[0] = self, args[1] = _cmd, args[2+] = actual arguments
            console.log("Called " + methodName);
            console.log("  arg1: " + ObjC.Object(args[2]));
            console.log("  arg2: " + ObjC.Object(args[3]));
        },
        onLeave: function(retval) {
            console.log("  Returned: " + ObjC.Object(retval));
        }
    });
}
```

### Recipe: iOS SSL Pinning Bypass

```javascript
// Use with frida_inject_script
if (ObjC.available) {
    // Disable SSL certificate validation
    var SSLSetSessionOption = Module.findExportByName(null, "SSLSetSessionOption");
    Interceptor.replace(SSLSetSessionOption, new NativeCallback(function(context, option, value) {
        if (option === 4) { // kSSLSessionOptionBreakOnServerAuth
            return 0;
        }
        return SSLSetSessionOption(context, option, value);
    }, 'int', ['pointer', 'int', 'bool']));
    
    // Hook SecTrustEvaluate
    var SecTrustEvaluate = Module.findExportByName(null, "SecTrustEvaluate");
    if (SecTrustEvaluate) {
        Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
            Memory.writeU32(result, 1); // kSecTrustResultProceed
            return 0;
        }, 'int', ['pointer', 'pointer']));
    }
    
    // AFNetworking bypass
    try {
        var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
        AFSecurityPolicy["- setSSLPinningMode:"].implementation = function(mode) {
            console.log("[*] AFNetworking SSL pinning disabled");
            return this["- setSSLPinningMode:"](0);
        };
        AFSecurityPolicy["- setAllowInvalidCertificates:"].implementation = function(allow) {
            return this["- setAllowInvalidCertificates:"](1);
        };
    } catch(e) {}
    
    console.log("[*] iOS SSL Pinning bypass loaded");
}
```

### Recipe: Bypass Jailbreak Detection

```javascript
// Use with frida_inject_script
if (ObjC.available) {
    // File existence checks
    var NSFileManager = ObjC.classes.NSFileManager;
    var fileExistsAtPath = NSFileManager["- fileExistsAtPath:"];
    
    Interceptor.attach(fileExistsAtPath.implementation, {
        onEnter: function(args) {
            this.path = ObjC.Object(args[2]).toString();
        },
        onLeave: function(retval) {
            var dominated = [
                "/Applications/Cydia.app",
                "/Library/MobileSubstrate",
                "/bin/bash",
                "/usr/sbin/sshd",
                "/etc/apt",
                "/private/var/lib/apt/"
            ];
            for (var i = 0; i < dominated.length; i++) {
                if (this.path.indexOf(dominated[i]) !== -1) {
                    console.log("[*] Hiding: " + this.path);
                    retval.replace(0);
                    return;
                }
            }
        }
    });
    
    // canOpenURL bypass
    var UIApplication = ObjC.classes.UIApplication;
    if (UIApplication) {
        var canOpenURL = UIApplication["- canOpenURL:"];
        Interceptor.attach(canOpenURL.implementation, {
            onEnter: function(args) {
                this.url = ObjC.Object(args[2]).toString();
            },
            onLeave: function(retval) {
                if (this.url.indexOf("cydia") !== -1) {
                    console.log("[*] Blocking canOpenURL: " + this.url);
                    retval.replace(0);
                }
            }
        });
    }
    
    console.log("[*] Jailbreak detection bypass loaded");
}
```

### Recipe: Dump Keychain Items

```javascript
// Use with frida_inject_script
if (ObjC.available) {
    var SecItemCopyMatching = Module.findExportByName(null, "SecItemCopyMatching");
    
    Interceptor.attach(SecItemCopyMatching, {
        onEnter: function(args) {
            this.query = new ObjC.Object(args[0]);
            this.result = args[1];
        },
        onLeave: function(retval) {
            if (retval.toInt32() === 0) { // errSecSuccess
                var result = Memory.readPointer(this.result);
                if (!result.isNull()) {
                    var obj = new ObjC.Object(result);
                    console.log("[Keychain] Query: " + this.query.toString());
                    console.log("[Keychain] Result: " + obj.toString());
                }
            }
        }
    });
    
    console.log("[*] Keychain hook installed");
}
```

### Recipe: Trace Crypto Operations

```javascript
// Use with frida_inject_script
if (ObjC.available) {
    var CCCrypt = Module.findExportByName(null, "CCCrypt");
    
    Interceptor.attach(CCCrypt, {
        onEnter: function(args) {
            var op = args[0].toInt32() === 0 ? "Encrypt" : "Decrypt";
            var algo = ["AES", "DES", "3DES", "CAST", "RC4", "RC2", "Blowfish"][args[1].toInt32()];
            var keyLen = args[4].toInt32();
            var key = args[3].readByteArray(keyLen);
            var dataLen = args[7].toInt32();
            
            console.log("[CCCrypt] " + op + " with " + algo);
            console.log("  Key (" + keyLen + " bytes): " + hexdump(key, {length: keyLen}));
        }
    });
}

function hexdump(buffer, options) {
    var bytes = new Uint8Array(buffer);
    var hex = "";
    for (var i = 0; i < bytes.length; i++) {
        hex += ("0" + bytes[i].toString(16)).slice(-2) + " ";
    }
    return hex;
}
```

---

## Desktop Recipes

### Recipe: Hook Windows API (CreateFile)

```javascript
// Use with frida_inject_script
var CreateFileW = Module.findExportByName("kernel32.dll", "CreateFileW");

Interceptor.attach(CreateFileW, {
    onEnter: function(args) {
        var filename = args[0].readUtf16String();
        console.log("[CreateFileW] " + filename);
    },
    onLeave: function(retval) {
        console.log("  Handle: " + retval);
    }
});
```

### Recipe: Hook Linux libc Functions

```javascript
// Use with frida_inject_script
var openPtr = Module.findExportByName("libc.so.6", "open");
var readPtr = Module.findExportByName("libc.so.6", "read");
var writePtr = Module.findExportByName("libc.so.6", "write");

Interceptor.attach(openPtr, {
    onEnter: function(args) {
        console.log("[open] " + args[0].readUtf8String());
    },
    onLeave: function(retval) {
        console.log("  fd: " + retval.toInt32());
    }
});

Interceptor.attach(readPtr, {
    onEnter: function(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.count = args[2].toInt32();
    },
    onLeave: function(retval) {
        var bytes = retval.toInt32();
        if (bytes > 0 && bytes < 1024) {
            console.log("[read] fd=" + this.fd + " bytes=" + bytes);
        }
    }
});
```

### Recipe: Hook macOS dylib Functions

```javascript
// Use with frida_inject_script
var dlopen = Module.findExportByName(null, "dlopen");

Interceptor.attach(dlopen, {
    onEnter: function(args) {
        var path = args[0];
        if (!path.isNull()) {
            console.log("[dlopen] " + path.readUtf8String());
        }
    }
});
```

---

## Memory Recipes

### Recipe: Search for String in Memory

```
frida_search_strings(
  session_id="session_xxx",
  pattern="password",
  case_sensitive=false,
  limit=50
)
```

### Recipe: Dump Memory Region

```
# First, find memory regions
frida_enumerate_ranges(session_id="session_xxx", protection="rw-")

# Then read a specific region
frida_memory_read(
  session_id="session_xxx", 
  address="0x7fff12340000",
  size=4096
)
```

### Recipe: Scan for Byte Pattern

```
# Search for pattern with wildcards
frida_memory_scan(
  session_id="session_xxx",
  pattern="48 89 5c 24 ?? 48 89 74 24",  # ?? = wildcard
  protection="r-x"  # Search in executable memory
)
```

### Recipe: Memory Patching (NOP slide)

```
# Write NOP instructions to disable a check
frida_memory_write(
  session_id="session_xxx",
  address="0x401234",
  data="90 90 90 90 90"  # 5 NOP instructions
)
```

### Recipe: Allocate and Use Memory

```javascript
// Use with frida_inject_script
// Allocate memory for our data
var buffer = Memory.alloc(256);
Memory.writeUtf8String(buffer, "Hello from Frida!");

// Use it in a function call
var puts = new NativeFunction(Module.findExportByName(null, "puts"), "int", ["pointer"]);
puts(buffer);
```

### Recipe: Watch Memory Address for Changes

```javascript
// Use with frida_inject_script
var targetAddress = ptr("0x12345678");
var lastValue = targetAddress.readU32();

setInterval(function() {
    var currentValue = targetAddress.readU32();
    if (currentValue !== lastValue) {
        console.log("[Memory Watch] " + targetAddress + ": " + lastValue + " -> " + currentValue);
        lastValue = currentValue;
    }
}, 100);
```

---

## Network Recipes

### Recipe: Trace All Network Connections

```
frida_trace(
  target="target_app",
  include=["connect", "send", "recv", "sendto", "recvfrom", "*SSL*", "*TLS*"],
  duration=60
)
```

### Recipe: Log DNS Queries

```javascript
// Use with frida_inject_script
var getaddrinfo = Module.findExportByName(null, "getaddrinfo");

Interceptor.attach(getaddrinfo, {
    onEnter: function(args) {
        var hostname = args[0].readUtf8String();
        console.log("[DNS] Resolving: " + hostname);
    }
});

// For gethostbyname (older)
var gethostbyname = Module.findExportByName(null, "gethostbyname");
if (gethostbyname) {
    Interceptor.attach(gethostbyname, {
        onEnter: function(args) {
            console.log("[DNS] gethostbyname: " + args[0].readUtf8String());
        }
    });
}
```

### Recipe: Intercept Socket Data

```javascript
// Use with frida_inject_script
var send = Module.findExportByName(null, "send");
var recv = Module.findExportByName(null, "recv");

Interceptor.attach(send, {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        var buf = args[1];
        var len = args[2].toInt32();
        
        console.log("[send] fd=" + fd + " len=" + len);
        if (len < 1024) {
            console.log(hexdump(buf.readByteArray(len)));
        }
    }
});

Interceptor.attach(recv, {
    onEnter: function(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
    },
    onLeave: function(retval) {
        var len = retval.toInt32();
        if (len > 0 && len < 1024) {
            console.log("[recv] fd=" + this.fd + " len=" + len);
            console.log(hexdump(this.buf.readByteArray(len)));
        }
    }
});

function hexdump(buffer) {
    var bytes = new Uint8Array(buffer);
    var hex = "";
    var ascii = "";
    var result = "";
    
    for (var i = 0; i < bytes.length; i++) {
        hex += ("0" + bytes[i].toString(16)).slice(-2) + " ";
        ascii += (bytes[i] >= 32 && bytes[i] < 127) ? String.fromCharCode(bytes[i]) : ".";
        
        if ((i + 1) % 16 === 0) {
            result += hex + " | " + ascii + "\n";
            hex = "";
            ascii = "";
        }
    }
    if (hex) {
        result += hex.padEnd(48) + " | " + ascii + "\n";
    }
    return result;
}
```

---

## Crypto Recipes

### Recipe: Hook OpenSSL

```javascript
// Use with frida_inject_script
var SSL_read = Module.findExportByName(null, "SSL_read");
var SSL_write = Module.findExportByName(null, "SSL_write");

if (SSL_read) {
    Interceptor.attach(SSL_read, {
        onEnter: function(args) {
            this.ssl = args[0];
            this.buf = args[1];
        },
        onLeave: function(retval) {
            var len = retval.toInt32();
            if (len > 0) {
                console.log("[SSL_read] " + len + " bytes");
                console.log(this.buf.readByteArray(Math.min(len, 256)));
            }
        }
    });
}

if (SSL_write) {
    Interceptor.attach(SSL_write, {
        onEnter: function(args) {
            var len = args[2].toInt32();
            console.log("[SSL_write] " + len + " bytes");
            console.log(args[1].readByteArray(Math.min(len, 256)));
        }
    });
}
```

### Recipe: Extract AES Keys

```javascript
// Use with frida_inject_script
// Hook common crypto functions to extract keys

// OpenSSL EVP
var EVP_EncryptInit_ex = Module.findExportByName(null, "EVP_EncryptInit_ex");
if (EVP_EncryptInit_ex) {
    Interceptor.attach(EVP_EncryptInit_ex, {
        onEnter: function(args) {
            var key = args[3];
            var iv = args[4];
            if (!key.isNull()) {
                console.log("[EVP_EncryptInit_ex]");
                console.log("  Key: " + hexdump(key.readByteArray(32)));
                if (!iv.isNull()) {
                    console.log("  IV:  " + hexdump(iv.readByteArray(16)));
                }
            }
        }
    });
}

// iOS CommonCrypto
var CCCryptorCreate = Module.findExportByName(null, "CCCryptorCreate");
if (CCCryptorCreate) {
    Interceptor.attach(CCCryptorCreate, {
        onEnter: function(args) {
            var op = args[0].toInt32() === 0 ? "Encrypt" : "Decrypt";
            var key = args[3];
            var keyLen = args[4].toInt32();
            var iv = args[5];
            
            console.log("[CCCryptorCreate] " + op);
            console.log("  Key (" + keyLen + "): " + hexdump(key.readByteArray(keyLen)));
            if (!iv.isNull()) {
                console.log("  IV: " + hexdump(iv.readByteArray(16)));
            }
        }
    });
}

function hexdump(buffer) {
    var bytes = new Uint8Array(buffer);
    var hex = "";
    for (var i = 0; i < bytes.length; i++) {
        hex += ("0" + bytes[i].toString(16)).slice(-2);
    }
    return hex;
}
```

### Recipe: Log All Hashing Operations

```javascript
// Use with frida_inject_script
var hashFunctions = [
    "CC_MD5", "CC_SHA1", "CC_SHA256", "CC_SHA512",  // iOS
    "MD5", "SHA1", "SHA256", "SHA512",               // OpenSSL
    "MD5_Final", "SHA1_Final", "SHA256_Final"        // OpenSSL
];

hashFunctions.forEach(function(name) {
    var addr = Module.findExportByName(null, name);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                console.log("[Hash] " + name + " called");
            }
        });
    }
});
```

---

## Anti-Detection Bypass

### Recipe: Hide Frida from Detection

```javascript
// Use with frida_inject_script
// Anti-detection measures

// 1. Hide frida-server process name
var strstr = Module.findExportByName(null, "strstr");
Interceptor.attach(strstr, {
    onEnter: function(args) {
        this.haystack = args[0].readUtf8String();
        this.needle = args[1].readUtf8String();
    },
    onLeave: function(retval) {
        if (this.needle && 
            (this.needle.indexOf("frida") !== -1 || 
             this.needle.indexOf("xposed") !== -1 ||
             this.needle.indexOf("substrate") !== -1)) {
            retval.replace(ptr(0));
        }
    }
});

// 2. Prevent port scanning for frida-server
var connect = Module.findExportByName(null, "connect");
Interceptor.attach(connect, {
    onEnter: function(args) {
        var sockaddr = args[1];
        var family = sockaddr.readU16();
        if (family === 2) { // AF_INET
            var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
            if (port === 27042 || port === 27043) { // Frida default ports
                console.log("[*] Blocking connection to Frida port " + port);
                this.block = true;
            }
        }
    },
    onLeave: function(retval) {
        if (this.block) {
            retval.replace(-1);
        }
    }
});

// 3. Hide frida libraries from /proc/maps
// (Android specific)
Java.perform(function() {
    try {
        var BufferedReader = Java.use("java.io.BufferedReader");
        BufferedReader.readLine.overload().implementation = function() {
            var line = this.readLine();
            if (line && (line.indexOf("frida") !== -1 || line.indexOf("gum") !== -1)) {
                return this.readLine(); // Skip this line
            }
            return line;
        };
    } catch(e) {}
});

console.log("[*] Anti-detection measures loaded");
```

### Recipe: Bypass Anti-Debugging

```javascript
// Use with frida_inject_script

// Linux/Android: ptrace anti-debug bypass
var ptrace = Module.findExportByName(null, "ptrace");
if (ptrace) {
    Interceptor.attach(ptrace, {
        onEnter: function(args) {
            this.request = args[0].toInt32();
        },
        onLeave: function(retval) {
            if (this.request === 0) { // PTRACE_TRACEME
                console.log("[*] Bypassing PTRACE_TRACEME");
                retval.replace(0);
            }
        }
    });
}

// iOS: sysctl anti-debug bypass
var sysctl = Module.findExportByName(null, "sysctl");
if (sysctl) {
    Interceptor.attach(sysctl, {
        onEnter: function(args) {
            this.mib = args[0];
            this.oldp = args[2];
        },
        onLeave: function(retval) {
            // Check for P_TRACED flag query
            var mib0 = this.mib.readS32();
            var mib1 = this.mib.add(4).readS32();
            if (mib0 === 1 && mib1 === 14) { // CTL_KERN, KERN_PROC
                // Clear P_TRACED flag
                var info = this.oldp;
                var flags = info.add(32); // Offset to p_flag
                var currentFlags = flags.readU32();
                flags.writeU32(currentFlags & ~0x800); // Clear P_TRACED
                console.log("[*] Cleared P_TRACED flag");
            }
        }
    });
}

// Windows: IsDebuggerPresent bypass
var IsDebuggerPresent = Module.findExportByName("kernel32.dll", "IsDebuggerPresent");
if (IsDebuggerPresent) {
    Interceptor.replace(IsDebuggerPresent, new NativeCallback(function() {
        console.log("[*] IsDebuggerPresent bypassed");
        return 0;
    }, 'int', []));
}

console.log("[*] Anti-debugging bypass loaded");
```

---

## Utility Functions

### Recipe: Pretty Print Objects (Android)

```javascript
// Use with frida_inject_script
function prettyPrint(obj) {
    if (obj === null || obj === undefined) {
        return "null";
    }
    
    Java.perform(function() {
        try {
            var cls = obj.getClass();
            var fields = cls.getDeclaredFields();
            console.log(cls.getName() + " {");
            
            for (var i = 0; i < fields.length; i++) {
                var field = fields[i];
                field.setAccessible(true);
                var name = field.getName();
                var value = field.get(obj);
                console.log("  " + name + " = " + value);
            }
            console.log("}");
        } catch(e) {
            console.log(obj.toString());
        }
    });
}
```

### Recipe: Stack Trace Logger

```javascript
// Use with frida_inject_script
function logStackTrace(label) {
    Java.perform(function() {
        var Exception = Java.use("java.lang.Exception");
        var e = Exception.$new();
        var stack = e.getStackTrace();
        
        console.log("[Stack Trace] " + label);
        for (var i = 0; i < Math.min(stack.length, 10); i++) {
            console.log("  " + stack[i].toString());
        }
    });
}
```

### Recipe: Native Stack Trace

```javascript
// Use with frida_inject_script
function logNativeStackTrace(context) {
    var bt = Thread.backtrace(context, Backtracer.ACCURATE);
    console.log("[Native Stack]");
    for (var i = 0; i < bt.length; i++) {
        var sym = DebugSymbol.fromAddress(bt[i]);
        console.log("  " + bt[i] + " " + sym.moduleName + "!" + sym.name);
    }
}
```

---

## Quick Reference

### Common Function Signatures

```javascript
// NativeFunction types
"void", "int", "uint", "long", "ulong", "float", "double", "pointer", "bool"

// Examples
new NativeFunction(addr, 'int', ['pointer', 'int']);      // func(char*, int) -> int
new NativeFunction(addr, 'void', []);                      // func(void) -> void
new NativeFunction(addr, 'pointer', ['pointer']);          // func(void*) -> void*
```

### Memory Read/Write

```javascript
ptr.readU8()          ptr.writeU8(val)
ptr.readU16()         ptr.writeU16(val)
ptr.readU32()         ptr.writeU32(val)
ptr.readU64()         ptr.writeU64(val)
ptr.readS8()          ptr.writeS8(val)
ptr.readFloat()       ptr.writeFloat(val)
ptr.readDouble()      ptr.writeDouble(val)
ptr.readPointer()     ptr.writePointer(val)
ptr.readUtf8String()  ptr.writeUtf8String(str)
ptr.readUtf16String() ptr.writeUtf16String(str)
ptr.readByteArray(n)  ptr.writeByteArray(arr)
```

### Common Protection Strings

```
"---" = No access
"r--" = Read only
"rw-" = Read/Write
"r-x" = Read/Execute (code)
"rwx" = Read/Write/Execute
```
