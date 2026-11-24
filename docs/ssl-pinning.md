# 三类证书校验的识别与绕过

iOS 上的证书校验基本落在三种实现里。先判断是哪一种，再决定打哪个点。

## 类型一：系统默认校验

App 直接走 `NSURLSession`，没有额外的校验逻辑。

**识别**：装好 mitmproxy CA 并信任后，就能直接看到明文。这种情况根本不需要 Frida。

**绕过**：无需绕过。

## 类型二：AFNetworking / TrustKit 等成熟库

**识别**：装了证书之后所有请求失败，控制台出现
`NSURLErrorServerCertificateUntrusted` 或 `kCFURLErrorCancelled`。

**绕过**：

| 库 | 目标方法 | 返回值 |
| --- | --- | --- |
| AFNetworking | `-[AFSecurityPolicy evaluateServerTrust:forDomain:]` | YES |
| TrustKit | `-[TSKPinningValidator evaluateTrust:forHostname:]` | 0 (ShouldAllowConnection) |
| Alamofire | 走系统层，被 `SecTrustEvaluate` 覆盖 | - |

## 类型三：自实现校验

**识别**：前两类都放行了，仍然握手失败。说明业务方自己拿证书做了比对。

常见写法：

1. 取服务端证书 `SecTrustCopyPublicKey` / `SecCertificateCopyData` 后与本地内置的证书做字节比对
2. 用 JSON 下发证书哈希，客户端本地算哈希比对
3. 把 `SecTrustEvaluate` 包进自己的封装函数

**定位方法**：跑 `frida/hook_template.js`，它会挂 `SecTrustEvaluate` 的观察点并打出调用栈，
栈上最近的那个业务方法就是目标。

**绕过**：把命中的类名和选择子加进 `ssl_pinning_bypass.js` 的 `EXTRA_TARGETS`。

## 验证顺序

```bash
# 1. 先确认代理链路本身是通的
curl -x 127.0.0.1:8080 https://httpbin.org/ip

# 2. 挂上绕过脚本
frida -U -f com.example.app -l frida/ssl_pinning_bypass.js --no-pause

# 3. 观察是否出现明文 Host
mitmdump -p 8080 --set flow_detail=1
```

三步走完还看不到明文，说明卡在了证书本身（不是校验逻辑），检查设备是否真的信任了 CA。
