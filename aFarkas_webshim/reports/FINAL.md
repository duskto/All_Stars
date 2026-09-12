# webshim 默认部署未认证上传到 RCE 漏洞报告（双利用链）

## 1. 结论

在 **默认 demo 部署模型** 下，本项目存在 **前认证任意文件上传 -> WebShell 落地 -> RCE**。

本次确认的两条可用利用链分别是：

1. `demos/demos/filereader/upload_json.php`  
2. `demos/demos/filereader/upload_html.php`

二者属于同一根因家族：**服务端直接信任上传文件名并写入 Web 可访问目录，且默认部署时该目录中的 `.php` 会被解释执行。**

---

## 2. 影响范围

### 2.1 受影响文件

- `demos/demos/filereader/upload_json.php`
- `demos/demos/filereader/upload_html.php`

### 2.2 风险等级

- **漏洞类型**：未认证任意文件上传
- **可升级影响**：前认证 RCE
- **风险等级**：P0

---

## 3. 利用点在哪里

### 3.1 利用点 A：`upload_json.php`

文件：`demos/demos/filereader/upload_json.php`

```php
2:     header('Content-Type: application/json');
3:     $directory = "upload/";
4:     $a = 0;
5:     echo "[";
6:     foreach ($_FILES['pictures']['name'] as $nameFile) {
7:         if (is_uploaded_file($_FILES['pictures']['tmp_name'][$a])) {
8:             $success = move_uploaded_file($_FILES['pictures']['tmp_name'][$a], $directory . $_FILES['pictures']['name'][$a]);
9:             if(!$success){
10:                 $success = 0;
11:             }
12:             echo '{"name": "'.$nameFile.'", "src": "'. $directory.$nameFile.'", "success": '.$success.'}';
13:         }
```

关键问题：

- `$_FILES['pictures']['name'][$a]` 直接参与目标路径拼接
- `move_uploaded_file(...)` 直接把攻击者上传的文件写到 `upload/`
- 返回值里把 `src` 直接回显，便于攻击者拿到落地 URL

### 3.2 利用点 B：`upload_html.php`

文件：`demos/demos/filereader/upload_html.php`

```php
2: if (isset($_POST['send'])) {
3:     $directory = "upload/";
4:     $a = 0;
5:     foreach ($_FILES['pictures']['name'] as $nameFile) {
6:         if (is_uploaded_file($_FILES['pictures']['tmp_name'][$a])) {
7:             move_uploaded_file($_FILES['pictures']['tmp_name'][$a], $directory . $_FILES['pictures']['name'][$a]);
8:             echo $nameFile  .': <img src="'. $directory.$nameFile.'" /><br />';
9:         }
```

关键问题：

- `isset($_POST['send'])` 只是一个可伪造字段，不是认证
- 同样直接使用原始文件名写入 `upload/`
- 返回 HTML 中直接泄露上传后的相对路径

---

## 4. 完整利用链

## 4.1 利用链 A：`upload_json.php` -> WebShell -> RCE

### 4.1.1 Source

- `$_FILES['pictures']['tmp_name'][$a]`
- `$_FILES['pictures']['name'][$a]`

### 4.1.2 中间检查

- `is_uploaded_file(...)`

该检查只能确认文件来自 HTTP POST 上传，**不能**检查：

- 扩展名
- MIME
- 魔数
- 上传目录是否可执行
- 文件名是否安全

### 4.1.3 Sink

- `move_uploaded_file(tmp, 'upload/' + 原始文件名)`

### 4.1.4 闭合路径

```text
攻击者构造 multipart/form-data
  -> POST /demos/demos/filereader/upload_json.php
  -> PHP 将文件写入 $_FILES['pictures']
  -> is_uploaded_file(...) 通过
  -> move_uploaded_file(...) 将 shell.php 写入 upload/shell.php
  -> 服务端 JSON 返回 src=upload/shell.php
  -> 攻击者 GET /demos/demos/filereader/upload/shell.php?cmd=id
  -> PHP 解释执行 shell.php
  -> 前认证 RCE
```

### 4.1.5 为什么这条链默认可打

在本次默认 Docker 部署中：

- `demos/` 被复制到 Apache Web 根目录
- `upload_json.php` 可直接访问
- 上传目录为 `/var/www/html/demos/demos/filereader/upload`
- Apache + mod_php 会解释 `.php`
- 未发现禁止该目录执行 PHP 的额外配置

因此上传后的 `.php` 会直接变成可访问的 WebShell。

---

## 4.2 利用链 B：`upload_html.php` -> WebShell -> RCE

### 4.2.1 Source

- `$_FILES['pictures']['tmp_name'][$a]`
- `$_FILES['pictures']['name'][$a]`
- `$_POST['send']`

### 4.2.2 中间检查

- `isset($_POST['send'])`
- `is_uploaded_file(...)`

其中 `send` 字段完全可由攻击者自行补上：

```http
Content-Disposition: form-data; name="send"

Upload
```

### 4.2.3 Sink

- `move_uploaded_file(tmp, 'upload/' + 原始文件名)`

### 4.2.4 闭合路径

```text
攻击者构造 multipart/form-data
  -> POST /demos/demos/filereader/upload_html.php
  -> 额外带上 send=Upload
  -> is_uploaded_file(...) 通过
  -> move_uploaded_file(...) 将 alt.php 写入 upload/alt.php
  -> HTML 响应中回显 <img src="upload/alt.php">
  -> 攻击者 GET /demos/demos/filereader/upload/alt.php?cmd=id
  -> PHP 解释执行 alt.php
  -> 前认证 RCE
```

---

## 5. 什么情况下可以利用

## 5.1 可直接利用为 RCE 的情况

满足以下条件时，可直接从上传闭合到 RCE：

1. `demos/demos/filereader/upload_json.php` 或 `upload_html.php` 被部署且可访问
2. 上传目录位于 Web 根目录内
3. 上传目录中的 `.php` 会被解释执行
4. 服务端没有对扩展名/MIME/魔数做强校验
5. 服务端没有把上传文件重命名为安全扩展

**本次默认 Docker 部署满足以上全部条件。**

## 5.2 只能形成“任意文件上传”，但不一定 RCE 的情况

如果部署者额外做了任一项：

- 禁止上传目录执行 PHP
- 仅将该目录作为静态文件目录
- 将上传文件强制改名为非脚本扩展
- 增加严格的服务端白名单校验

则漏洞可能退化为：

- 未认证任意文件上传
- 内容托管
- 潜在存储型 XSS / 覆盖风险

但 **不一定** 能直接闭合到 RCE。

## 5.3 不可利用的情况

以下情况下，这条链不成立：

- 项目仅作为前端库使用，`demos/*.php` 根本未部署
- Web 服务器不解析上传目录中的 `.php`
- 反向代理或 WAF 从入口处阻断了上传点

---

## 6. 为什么前端“限制”不构成防护

### 6.1 `accept="image/*"` 不是服务端验证

前端示例页面中存在：

- `demos/demos/filereader/index.html:210`
- `demos/demos/filereader/index.html:227`
- `demos/demos/filereader/multi.html:240`
- `demos/demos/filereader/multi.html:257`

但这只是浏览器提示，攻击者可直接用：

- `curl`
- Burp Repeater
- Python `requests`

发送任意 multipart 请求。

### 6.2 JS 预览逻辑不参与安全决策

前端对 `file.type.indexOf('image/')` 的判断只影响预览，不影响服务端接收和落盘。

---

## 7. 默认 Docker 部署下的实测验证

### 7.1 验证环境

- 日期：2026-05-11
- 部署方式：本仓库 `docker compose up -d --build`
- 访问地址：`http://127.0.0.1:8080/`
- PHP 运行方式：`php:8.3-apache`

### 7.2 链 A 验证结果

执行脚本：

```bash
python3 reports/exp_upload_json_rce.py http://127.0.0.1:8080 id
```

成功结果：

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 7.3 链 B 验证结果

执行脚本：

```bash
python3 reports/exp_upload_html_rce.py http://127.0.0.1:8080 id
```

成功结果：

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

两条链都已在默认 Docker 部署下验证成功。

---

## 8. 漏洞影响

攻击者在无需认证的情况下可以：

- 上传任意 PHP WebShell
- 以 Web 服务身份执行系统命令
- 读取站点源码与配置
- 横向利用站点可访问资源
- 持久化后门文件

在本次环境中，命令执行身份为：

- `www-data`

---

## 9. 修复建议

至少同时做以下几项：

1. **不要在生产环境部署 demo 上传脚本**
2. 上传目录放到 **Web 根目录之外**
3. 对上传文件执行：
   - 扩展名白名单
   - MIME/魔数双重校验
   - 随机文件名重命名
4. 明确禁止上传目录执行脚本：
   - Apache：关闭该目录 PHP 解释
   - Nginx：不要把该目录交给 PHP-FPM
5. 删除演示用途的直传回显逻辑

---

## 10. 最终判断

- **前认证 RCE：成立**
- **默认 Docker 部署下：可直接利用**
- **认证绕过后 RCE：不适用，本仓库内无真实认证边界**

