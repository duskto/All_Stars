# 匿名漏洞报告复核报告（前认证RCE）

- 复核日期：2026-04-02
- 项目路径：`d:\破壳项目\102_CSAILVision_LabelMeAnnotationTool`
- 被复核对象：
  - `./reports/preauth_rce_漏洞分析报告.md`
  - `./漏洞信息/2032383940492517378.pdf`
  - `./漏洞信息/2032383945617956865.pdf`
- 复核目标：确认“前认证RCE”是否可由真实 Web 请求路由触发、是否存在有效过滤、并评估漏洞报告质量。

---

## 1. 路由可达性（真实 Web 触发面）

本项目不是集中式后端路由框架，前端直接请求脚本路径；因此“可触发性”取决于脚本 URL 是否可访问。

### 1.1 路由证据

1. 前端实际调用 `saveimage.php`：

```js
// annotationTools/js/scribble.js:142-151  (函数: this.save)
$.ajax({
  type: "POST",
  url: "annotationTools/php/saveimage.php",
  data: { image: dataURL, name: imname, uploadDir: dir }
});
```

2. 前端实际调用 `createdir.php`：

```js
// annotationTools/js/scribble.js:159-166  (函数: this.createDir)
$.ajax({
  type: "POST",
  url: "annotationTools/php/createdir.php",
  data: { urlData: url }
});
```

3. 前端实际调用 `fetch_image.cgi` / `fetch_prev_image.cgi`：

```js
// annotationTools/js/file_info.js:341-343  (函数: this.FetchImage)
var url = 'annotationTools/perl/fetch_image.cgi?mode=' + this.mode + ...;

// annotationTools/js/file_info.js:366-370  (函数: this.FetchPrevImage)
var url = 'annotationTools/perl/fetch_prev_image.cgi?mode=' + this.mode + ...;
```

4. 前端实际调用 `getpackfile.php`：

```js
// annotationTools/js/startup.js:312-315 (函数: StartupLabelMe 内字符串构造)
<form action="annotationTools/php/getpackfile.php" method="post" id="packform">
```

5. CGI 允许执行（Web 服务器配置）：

```apache
# .htaccess:1-2
Options +Includes +ExecCGI
AddHandler cgi-script .cgi .sh .pl
```

6. README 明确依赖 Apache + CGI + PHP：
- `README.md:84-87`

结论：上述脚本路径均属于真实可触发 Web 攻击面，不是“死代码”。

---

## 2. 匿名报告中的“前认证RCE”复核结论

### 2.1 结论总览

- `saveimage.php` 前认证 RCE：**成立（高危，直接链）**
- `fetch_image.cgi/fetch_prev_image.cgi` 命令注入：**语义成立（中高危，条件链）**
- `getpackfile.php` 被标成“上传导致RCE”：**不成立（误分类，偏离主链）**

---

## 3. 漏洞 1：`saveimage.php` 前认证任意文件写入 -> RCE（成立）

### 3.1 代码段与函数定位

文件：`annotationTools/php/saveimage.php`（`<global>`）

```php
// saveimage.php:6-7
if ( isset($_POST["image"]) && !empty($_POST["image"]) ) {
    define('UPLOAD_DIR', $_POST["uploadDir"]);

// saveimage.php:13-17
$parts = explode(',', $dataURL);
$data = $parts[1];
$data = base64_decode($data);

// saveimage.php:20-23
$file = $TOOLHOME . UPLOAD_DIR . $_POST["name"];
$success = file_put_contents($file, $data);
```

### 3.2 攻击者视角利用链（真实路由）

1. 向 `POST /annotationTools/php/saveimage.php` 发送请求（无需登录）。
2. 通过参数控制写入路径：`uploadDir` + `name`。
3. 通过 `image` 提供 base64 内容，服务端解码后原样落盘。
4. 若写入 `.php` 到可访问目录（如 `annotationTools/php/`），再 `GET` 该文件触发代码执行。

### 3.3 过滤/拦截检查（是否存在）

未发现有效过滤：

- 无认证校验（未检查 session/token）
- 无路径规范化/白名单（`basename`/`realpath`/目录约束均无）
- 无后缀白名单（可写 `.php`）
- 无 MIME/魔数校验（仅 `explode + base64_decode`）
- 无执行隔离策略（仓库内无“上传目录禁执行”配置）

### 3.4 开发者视角现实性校验

该链在“按官方文档部署”时更容易成立：

- `Makefile:19-25` 对多个目录（含 `annotationTools/php`）赋予高写权限。
- `README.md:84-87` 明确要求 CGI/PHP 运行。

因此此问题不是理论漏洞，而是典型可落地前认证 RCE。

我已通过部署本地项目测试，成功RCE
---

## 4. 漏洞 2：`fetch_image.cgi` / `fetch_prev_image.cgi` 命令注入（条件成立）

### 4.1 代码段与函数定位

文件：
- `annotationTools/perl/fetch_image.cgi`（`<global>`）
- `annotationTools/perl/fetch_prev_image.cgi`（`<global>`）

关键片段：

```perl
# fetch_image.cgi:13,20,27
my $collection = $query->param("collection");
my $fname = $LM_HOME . "annotationCache/DirLists/$collection.txt";
open(NUMLINES,"wc -l $fname |");
```

`fetch_prev_image.cgi` 同构位置：`13/20/27`、`45/52`、`70/77`。

### 4.2 可利用性判定

- 命令拼接语义：**存在**（用户输入进入 shell 命令字符串）
- 直接触发门槛：`open(FP,$fname)` 需先成功（脚本在该检查失败时直接返回）

因此：
- 这是**真实漏洞**，但“单请求直接 RCE”通常受文件存在约束。
- 与 `saveimage.php` 组合后（先写可控文件名到 `annotationCache/DirLists/`）可解锁该约束。

### 4.3 与前认证 RCE关系

该链可形成“前认证多步 RCE”，但在本项目里存在更短路径（漏洞 1 直接写 PHP 并执行），因此该链属于次级价值路径。

---

## 5. 关于过滤是否存在（最终判定）

针对“文件上传/落盘链路”，当前后端**不存在有效安全过滤**。

- `saveimage.php`：仅检查 `image` 非空，不限制路径、后缀、内容类型。
- `createdir.php`：`mkdir($TOOLHOME.$dirURL, 0777, true)`，无路径约束。
- `getpackfile.php`：并非上传接口，不应当作为“上传过滤”证据。

结论：如果问题定义为“上传（落盘）是否存在安全过滤”，答案是：**不存在可防御攻击的服务端过滤**。

---

## 6. 对 `./reports/preauth_rce_漏洞分析报告.md` 的复核评价

优点：

1. 主结论正确：`saveimage.php` 可构成前认证 RCE。
2. 给出了清晰主链和关键行号。
3. 辅助指出了 `fetch_*` 命令拼接风险。

不足：

1. 对“触发前提”描述偏简：未明确 `fetch_*` 链路受 `open(FP,$fname)` 成功条件约束。
2. 未充分区分“直接可用链”（saveimage）和“条件链”（fetch_*）的利用成本。
3. 未明确强调 `Makefile` 默认高写权限对可利用性的放大作用。

总体评价：**有效（中上）**，但还可增强“可利用条件精度”。

---

## 7. 对 `./漏洞信息` 两份 PDF 报告的效果评估

### 7.1 有效点

1. 覆盖到了 `saveimage.php` 关键危险点（输入到 `file_put_contents`）。
2. 覆盖到了 `getpackfile.php` 的可疑文件操作点。

### 7.2 问题点

1. 标签/定位混乱：
   - 报告显示“所处文件 createdir.php”，但证据路径多次落在 `getpackfile.php`/`saveimage.php`。
2. 重复告警较多：同一链路重复列出，降低可读性。
3. 缺乏路由可达性验证：没有证明“从真实 Web 请求可触发”。
4. 缺乏利用链分层：未区分“直接 RCE”与“条件链”。
5. 漏报关键点：未覆盖 `fetch_image.cgi/fetch_prev_image.cgi` 的命令拼接。

### 7.3 效果结论

- 作为“初筛提示”有价值。
- 作为“可直接用于修复优先级决策”的报告质量不足。
- 建议评级：**中等偏下（更像规则扫描输出，不是可利用性审计报告）**。

---

## 8. 修复优先级建议（开发维护视角）

1. **P0**：下线或鉴权 `saveimage.php` / `createdir.php`。
2. **P0**：`saveimage.php` 强制固定目录与固定后缀（仅 `.png`），增加内容魔数校验。
3. **P1**：移除 `fetch_*` 中 `open(..., "cmd |")`，改为无 shell 的安全实现。
4. **P1**：部署层禁止可写目录执行 PHP。
5. **P1**：移除 `Makefile` 中对 `annotationTools/php` 的 `777` 权限设置，改最小权限。

---

## 9. 最终复核结论

- 匿名报告中“前认证RCE存在”的核心判断：**正确**。
- 该漏洞可被真实 Web 路由触发，且当前几乎无有效过滤。
- `./漏洞信息` 报告可做线索输入，但不能替代代码级可利用性复核。
