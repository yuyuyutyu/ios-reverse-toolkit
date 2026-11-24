"use strict";

/**
 * ssl_pinning_bypass.js
 *
 * 通用证书校验绕过。分四层处理：
 *   1. Security 框架的 C 接口（系统层，覆盖绝大多数 App）
 *   2. NSURLRequest 的全局放行开关
 *   3. 常见第三方库与自实现校验方法
 *   4. 越狱检测的文件探测白名单
 *
 * 用法：
 *   frida -U -f <bundleId> -l ssl_pinning_bypass.js --no-pause
 *   frida -U <进程名> -l ssl_pinning_bypass.js
 */

var TAG = "[pinning] ";
function log(msg) { console.log(TAG + msg); }

/**
 * 自实现校验通常挂在业务方自己的类上，名字五花八门。
 * 命中不了的时候用 hook_template.js 枚举方法，把命中的类名/选择子加到这里。
 */
var EXTRA_TARGETS = [
    // ["<ClassName>", "- <selector>:<arg>:"],
];

/**
 * 越狱检测常见的探测路径。命中这些路径的 fileExists 一律返回 false，
 * 其他路径保持原行为，避免把 App 的正常文件访问一起打死。
 */
var JAILBREAK_PATHS = [
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Library/MobileSubstrate",
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/usr/sbin/frida-server",
    "/usr/bin/ssh",
    "/bin/bash",
    "/etc/apt",
];

if (!ObjC.available) {
    log("当前进程不是 Objective-C 环境，脚本不适用");
} else {
    bypassSecTrust();
    bypassURLRequest();
    bypassThirdParty();
    bypassJailbreakCheck();
}

/* ---------------- 1. Security 框架 C 接口 ---------------- */

function replaceCFunction(symbol, retType, argTypes, callback) {
    var addr = Module.findExportByName("Security", symbol);
    if (addr === null) {
        log("未找到 " + symbol + "，跳过");
        return;
    }
    Interceptor.replace(addr, new NativeCallback(callback, retType, argTypes));
    log("已替换 Security." + symbol);
}

function bypassSecTrust() {
    replaceCFunction("SecTrustEvaluate", "int", ["pointer", "pointer"],
        function (trust, resultPtr) {
            if (!resultPtr.isNull()) {
                resultPtr.writeU32(1); // kSecTrustResultProceed
            }
            return 0; // errSecSuccess
        });

    replaceCFunction("SecTrustEvaluateWithError", "bool", ["pointer", "pointer"],
        function (trust, errorPtr) {
            if (!errorPtr.isNull()) {
                errorPtr.writePointer(ptr(0));
            }
            return 1; // true
        });

    replaceCFunction("SecTrustGetTrustResult", "int", ["pointer", "pointer"],
        function (trust, resultPtr) {
            if (!resultPtr.isNull()) {
                resultPtr.writeU32(1);
            }
            return 0;
        });
}

/* ---------------- 2. NSURLRequest 全局放行 ---------------- */

function bypassURLRequest() {
    var cls = ObjC.classes.NSURLRequest;
    if (!cls) {
        return;
    }
    var method = cls["+ allowsAnyHTTPSCertificateForHost:"];
    if (!method) {
        log("NSURLRequest 未暴露 allowsAnyHTTPSCertificateForHost:，跳过");
        return;
    }
    Interceptor.attach(method.implementation, {
        onLeave: function (retval) {
            retval.replace(1);
        }
    });
    log("已放行 NSURLRequest +allowsAnyHTTPSCertificateForHost:");
}

/* ---------------- 3. 第三方与自实现校验 ---------------- */

function hookToValue(className, selector, value) {
    var cls = ObjC.classes[className];
    if (!cls) {
        log("跳过 " + className + "（未加载）");
        return false;
    }
    var method = cls[selector];
    if (!method) {
        log("跳过 " + className + " " + selector + "（无此方法）");
        return false;
    }
    Interceptor.attach(method.implementation, {
        onLeave: function (retval) {
            retval.replace(value);
        }
    });
    log("已放行 " + className + " " + selector);
    return true;
}

function bypassThirdParty() {
    // AFNetworking：返回 YES 表示信任该服务端证书
    hookToValue("AFSecurityPolicy", "- evaluateServerTrust:forDomain:", 1);

    // TrustKit：返回 0 对应 TSKTrustDecisionShouldAllowConnection
    hookToValue("TSKPinningValidator", "- evaluateTrust:forHostname:", 0);

    // 部分封装把校验封在 session 回调里，直接切到「使用凭据」分支
    hookToValue("AFURLSessionManager",
        "- URLSession:didReceiveAuthenticationChallenge:completionHandler:", 0);

    EXTRA_TARGETS.forEach(function (pair) {
        hookToValue(pair[0], pair[1], 1);
    });
}

/* ---------------- 4. 越狱检测文件探测 ---------------- */

function bypassJailbreakCheck() {
    var cls = ObjC.classes.NSFileManager;
    if (!cls) {
        return;
    }
    var method = cls["- fileExistsAtPath:"];
    if (!method) {
        return;
    }
    Interceptor.attach(method.implementation, {
        onEnter: function (args) {
            this.path = "";
            try {
                this.path = new ObjC.Object(args[2]).toString();
            } catch (e) {
                this.path = "";
            }
        },
        onLeave: function (retval) {
            for (var i = 0; i < JAILBREAK_PATHS.length; i++) {
                if (this.path.indexOf(JAILBREAK_PATHS[i]) === 0) {
                    log("拦截越狱探测: " + this.path);
                    retval.replace(0);
                    return;
                }
            }
        }
    });
    log("已挂载越狱路径探测拦截（白名单 " + JAILBREAK_PATHS.length + " 条）");
}
