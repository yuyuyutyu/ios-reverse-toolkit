# iOS 抓包环境搭建 SOP

## 前置条件

- macOS 或 Linux 一台，与手机处于同一局域网
- 目标设备：真机（模拟器无法复现证书校验行为）
- Frida 与设备端 frida-server 版本必须一致

## 步骤

### 1. 装代理

```bash
pip install mitmproxy
mitmproxy -s mitmproxy/req_rewrite.py -p 8080
```

### 2. 设备侧配置

1. Wi-Fi → 当前网络 → 配置代理 → 手动 → 填主机 IP 与 8080
2. Safari 打开 `http://mitm.it`，选 iOS 下载描述文件
3. 设置 → 已下载描述文件 → 安装
4. 设置 → 通用 → 关于本机 → 证书信任设置 → 打开 mitmproxy 的完全信任

第 4 步最容易漏。漏了会出现「证书已装但仍然明文不通」。

### 3. 确认链路

```bash
curl -x 127.0.0.1:8080 https://httpbin.org/ip
```

有正常响应说明代理可用。

### 4. 处理证书校验

按 [ssl-pinning.md](ssl-pinning.md) 判断类型后挂对应脚本。

## 常见问题

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| 打开 App 就闪退 | 越狱 / 调试检测 | 脚本里的路径白名单钩子，或先关掉 Frida 冷启动再 attach |
| 只有部分请求能解密 | 部分 SDK 自带校验 | 定位那个 SDK 的类，加进 EXTRA_TARGETS |
| 装完证书后所有 HTTPS 全断 | 设备没信任 CA | 回到步骤 2 第 4 步 |
| frida-ps 看不到进程 | frida-server 没跑或版本不匹配 | 重启 frida-server，对齐版本 |
