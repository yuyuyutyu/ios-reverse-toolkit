"use strict";

/**
 * hook_template.js
 *
 * 起步模板：不确定目标 App 用哪个类做证书校验时，先用这个把方法和调用栈打出来，
 * 再把命中的类名 / 选择子写进 ssl_pinning_bypass.js 的 EXTRA_TARGETS。
 */

var TAG = "[hook] ";
function log(msg) { console.log(TAG + msg); }

/* 需要重点关注的类名关键字 —— 按目标 App 的实际结构改 */
var WATCH_KEYWORDS = [
    "Pinning",
    "SSL",
    "Trust",
    "Certificate",
    "Security",
    "Network"
];

/* 需要挂观察点的系统符号 */
var WATCH_SYMBOLS = [
    ["Security", "SecTrustEvaluate"],
    ["Security", "SecTrustEvaluateWithError"],
    ["Security", "SecTrustGetTrustResult"]
];

if (!ObjC.available) {
    log("非 ObjC 环境");
} else {
    enumerateWatchClasses();
    watchTrustCalls();
}

/* 1. 把可疑类的自有方法全部列出来 */
function enumerateWatchClasses() {
    Object.keys(ObjC.classes).forEach(function (name) {
        var lower = name.toLowerCase();
        var hit = WATCH_KEYWORDS.some(function (kw) {
            return lower.indexOf(kw.toLowerCase()) >= 0;
        });
        if (!hit) {
            return;
        }
        log("== " + name);
        var methods = ObjC.classes[name].$ownMethods || [];
        methods.forEach(function (sel) {
            log("    " + sel);
        });
    });
}

/* 2. 运行期观察：谁在调用证书校验，调用栈是什么 */
function watchTrustCalls() {
    WATCH_SYMBOLS.forEach(function (pair) {
        var addr = Module.findExportByName(pair[0], pair[1]);
        if (addr === null) {
            return;
        }
        Interceptor.attach(addr, {
            onEnter: function (args) {
                var frames = Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress)
                    .join("\n    ");
                log("调用 " + pair[1] + "\n    " + frames);
            }
        });
        log("已挂观察点 " + pair[0] + "." + pair[1]);
    });
}
