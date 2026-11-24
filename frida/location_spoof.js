"use strict";

/**
 * location_spoof.js
 *
 * 位置数据注入。用于验证 App 的位置校验逻辑是否可靠
 * （例如签到类功能是否只在客户端做距离判断）。
 *
 * 用法：
 *   frida -U -f <bundleId> -l location_spoof.js --no-pause
 */

/* ===================== 配置区 ===================== */
var FAKE_LAT = 22.543099;    // 纬度
var FAKE_LON = 114.057868;   // 经度
var FAKE_ALT = 20.0;         // 海拔
var FAKE_HACC = 5.0;         // 水平精度（米）
/* ================================================== */

var TAG = "[location] ";
function log(msg) { console.log(TAG + msg); }

if (!ObjC.available) {
    log("当前进程不是 Objective-C 环境，脚本不适用");
} else {
    hookCoordinate();
    hookManagerLocation();
}

/* 1. 直接接管 -[CLLocation coordinate]，结构体返回交给 Frida 处理 ABI */
function hookCoordinate() {
    var CLLocation = ObjC.classes.CLLocation;
    if (!CLLocation) {
        log("CLLocation 未加载");
        return;
    }
    var method = CLLocation["- coordinate"];
    if (!method) {
        log("未找到 -[CLLocation coordinate]");
        return;
    }
    Interceptor.replace(method.implementation, new NativeCallback(
        function (self, sel) {
            return { latitude: FAKE_LAT, longitude: FAKE_LON };
        },
        { latitude: "double", longitude: "double" },
        ["pointer", "pointer"]
    ));
    log("已接管 -[CLLocation coordinate] -> " + FAKE_LAT + ", " + FAKE_LON);
}

/* 2. 让 CLLocationManager 的 location 直接返回构造好的假对象 */
function hookManagerLocation() {
    var CLLocation = ObjC.classes.CLLocation;
    if (!CLLocation) {
        return;
    }

    var fake = null;
    try {
        fake = CLLocation.alloc().initWithLatitude_longitude_(FAKE_LAT, FAKE_LON);
        if (fake && fake.respondsToSelector_(ObjC.selector("setAltitude:"))) {
            fake.setAltitude_(FAKE_ALT);
        }
        if (fake && fake.respondsToSelector_(ObjC.selector("setHorizontalAccuracy:"))) {
            fake.setHorizontalAccuracy_(FAKE_HACC);
        }
    } catch (e) {
        log("构造假 CLLocation 失败: " + e.message);
        return;
    }

    var Manager = ObjC.classes.CLLocationManager;
    if (!Manager) {
        log("CLLocationManager 未加载");
        return;
    }
    var method = Manager["- location"];
    if (!method) {
        log("未找到 -[CLLocationManager location]");
        return;
    }
    var handle = fake.handle;
    Interceptor.attach(method.implementation, {
        onLeave: function (retval) {
            retval.replace(handle);
        }
    });
    log("已接管 -[CLLocationManager location]");
}
