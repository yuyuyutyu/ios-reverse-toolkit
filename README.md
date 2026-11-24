# ios-reverse-toolkit

iOS 应用流量分析、证书校验绕过与应用重签名 —— 一套拿来就能跑的实践工具链。

![Frida](https://img.shields.io/badge/Frida-16.x-orange)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## 它解决什么问题

移动端 App 的网络调试有三道坎，这个仓库把三道坎拆开处理：

| 坑 | 现象 | 对应方案 |
| --- | --- | --- |
| 证书校验（SSL Pinning） | 装了代理证书仍然看不到明文，连接被直接断开 | `frida/ssl_pinning_bypass.js` + `docs/ssl-pinning.md` |
| 越狱 / 调试检测 | 一挂 Frida 就闪退 | `frida/ssl_pinning_bypass.js` 里的路径白名单钩子 |
| 签名校验 | 改过的包装不进设备 | `scripts/resign_ipa.sh` |

## 目录结构

| 路径 | 说明 |
| --- | --- |
| `frida/ssl_pinning_bypass.js` | 证书校验绕过，覆盖 Security 框架 C 接口与常见第三方实现 |
| `frida/location_spoof.js` | 位置数据注入，用于验证 App 的位置校验逻辑 |
| `frida/hook_template.js` | 类与方法枚举、Hook 骨架 |
| `mitmproxy/req_rewrite.py` | 请求拦截、响应体重写、域名拦截 addon |
| `scripts/resign_ipa.sh` | IPA 重签名一键脚本 |
| `docs/ssl-pinning.md` | 三类证书校验实现的绕过路径 |
| `docs/ios-capture-sop.md` | 抓包环境搭建 SOP |

## 快速开始

### 1. 启动代理

```bash
pip install mitmproxy
mitmproxy -s mitmproxy/req_rewrite.py -p 8080
```

手机侧把 Wi-Fi 代理指向运行 mitmproxy 的机器，访问 http://mitm.it 安装 CA 证书，
再到「设置 → 通用 → 关于本机 → 证书信任设置」里打开完全信任。

### 2. 绕过证书校验

```bash
frida-ps -U                                   # 确认设备与目标进程
frida -U -f com.example.app \
      -l frida/ssl_pinning_bypass.js --no-pause
```

连上以后代理侧应该能看到明文请求。看不到就把控制台里「已放行」的类名对一遍，
缺的按 `EXTRA_TARGETS` 追加。

### 3. 验证绕过是否生效

```bash
mitmdump -s mitmproxy/req_rewrite.py --set flow_detail=1
```

## 适用场景

自有 App 的安全测试，以及取得书面授权的测试环境。
脚本只做函数替换与流量改写，不含任何针对第三方的攻击载荷。

## License

MIT
