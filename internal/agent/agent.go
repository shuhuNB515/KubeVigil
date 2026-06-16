package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/shuhuNB515/KubeVigil/internal/config"
	"github.com/shuhuNB515/KubeVigil/internal/event"
	"github.com/shuhuNB515/KubeVigil/internal/k8s"
	"github.com/shuhuNB515/KubeVigil/internal/rules"
)

// 事件类型常量（与 eBPF C 代码对应）
const (
	eventTypeExecve  = 1
	eventTypeOpen    = 2
	eventTypeConnect = 3
)

// eBPF 事件结构（与 C 代码对应，必须保持内存布局一致）
// 注意：Go 结构体字段顺序必须与 C 结构体完全一致，
// 且使用 _pad 字段确保对齐，避免 binary.Read 解析错位。

type bpfExecveEvent struct {
	Type      uint32
	PID       uint32
	PPID      uint32
	TID       uint32
	Timestamp uint64
	Comm      [64]byte
	Filename  [256]byte
	Args      [256]byte
	CgroupID  uint32
	_pad      uint32 // 对齐到 8 字节边界
}

type bpfOpenEvent struct {
	Type      uint32
	PID       uint32
	PPID      uint32
	TID       uint32
	Timestamp uint64
	Comm      [64]byte
	Path      [256]byte
	Flags     int32
	CgroupID  uint32
	_pad      uint32 // 对齐到 8 字节边界
}

type bpfConnectEvent struct {
	Type      uint32
	PID       uint32
	PPID      uint32
	TID       uint32
	Timestamp uint64
	Comm      [64]byte
	IPVersion uint8
	_pad1     [3]byte // 对齐 IP 字段
	IP        [16]byte
	Port      uint16
	_pad2     uint16 // 对齐 CgroupID
	CgroupID  uint32
}

// Agent 运行时安全代理
type Agent struct {
	cfg     *config.Config
	rules   *rules.Engine
	k8s     *k8s.Resolver
	eventCh chan *event.EnrichedEvent
	alertCh chan *event.Alert
}

// New 创建 Agent
func New(cfg *config.Config) (*Agent, error) {
	// 初始化规则引擎
	ruleEngine := rules.NewEngine()
	if cfg.Rules.RulesFile != "" {
		if err := ruleEngine.LoadRules(cfg.Rules.RulesFile); err != nil {
			log.Printf("[Agent] 加载规则文件失败，使用默认规则: %v", err)
			ruleEngine.LoadDefaultRules()
		}
	} else {
		ruleEngine.LoadDefaultRules()
	}

	// 初始化 K8s Resolver
	var resolver *k8s.Resolver
	resolver, err := k8s.NewResolver()
	if err != nil {
		log.Printf("[Agent] K8s Resolver 初始化失败（非 K8s 环境？）: %v", err)
	}

	return &Agent{
		cfg:     cfg,
		rules:   ruleEngine,
		k8s:     resolver,
		eventCh: make(chan *event.EnrichedEvent, 1024),
		alertCh: make(chan *event.Alert, 256),
	}, nil
}

// Run 启动 Agent
func (a *Agent) Run(ctx context.Context) error {
	// 设置日志级别
	a.setupLogging()

	// 移除内存锁限制
	if err := rlimit.RemoveMemLock(); err != nil {
		return fmt.Errorf("移除内存锁限制失败: %w", err)
	}

	// 加载编译好的 eBPF 程序
	collection, err := a.loadBPFProgram()
	if err != nil {
		return fmt.Errorf("加载 eBPF 程序失败: %w", err)
	}
	defer collection.Close()

	// 挂载 tracepoint
	links, err := a.attachProbes(collection)
	if err != nil {
		return fmt.Errorf("挂载探针失败: %w", err)
	}
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	// 打开 Ring Buffer Reader
	reader, err := ringbuf.NewReader(collection.Maps["events"])
	if err != nil {
		return fmt.Errorf("打开 Ring Buffer 失败: %w", err)
	}
	// 注意：不在此处 defer reader.Close()，而是在退出时手动关闭以控制时序

	// 启动 K8s Resolver
	if a.k8s != nil {
		a.k8s.Start(ctx)
	}

	// 启动规则热重载监听
	if a.cfg.Rules.RulesFile != "" {
		go a.watchRulesReload(ctx)
	}

	// 启动事件处理协程
	go a.processEvents(ctx)
	go a.processAlerts(ctx)

	log.Println("[Agent] KubeVigil 守夜人已启动，正在监听...")
	log.Printf("[Agent] 已加载 %d 条安全规则", a.rules.GetRuleCount())

	// 读取事件循环
	go a.readEvents(ctx, reader)

	// 等待退出信号
	<-ctx.Done()
	log.Println("[Agent] KubeVigil 守夜人正在关闭...")

	// 关闭 Ring Buffer Reader 以中断阻塞读取
	if err := reader.Close(); err != nil {
		log.Printf("[Agent] 关闭 Ring Buffer 失败: %v", err)
	}

	return nil
}

// loadBPFProgram 加载 eBPF 程序
func (a *Agent) loadBPFProgram() (*ebpf.Collection, error) {
	// 尝试从 BPF ELF 文件加载
	bpfPath := "/etc/kubevigil/probes.o"
	if _, err := os.Stat(bpfPath); err != nil {
		bpfPath = "bpf/probes.o"
	}

	spec, err := ebpf.LoadCollectionSpec(bpfPath)
	if err != nil {
		return nil, fmt.Errorf("加载 BPF spec 失败: %w", err)
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("创建 BPF Collection 失败: %w", err)
	}

	return collection, nil
}

// attachProbes 挂载探针
func (a *Agent) attachProbes(collection *ebpf.Collection) ([]link.Link, error) {
	var links []link.Link

	if a.cfg.Probe.Execve {
		l, err := link.Tracepoint("syscalls", "sys_enter_execve", collection.Programs["trace_execve"], nil)
		if err != nil {
			return links, fmt.Errorf("挂载 execve 探针失败: %w", err)
		}
		links = append(links, l)
		log.Println("[Agent] execve 探针已挂载")
	}

	if a.cfg.Probe.Open {
		l, err := link.Tracepoint("syscalls", "sys_enter_openat", collection.Programs["trace_openat"], nil)
		if err != nil {
			return links, fmt.Errorf("挂载 open 探针失败: %w", err)
		}
		links = append(links, l)
		log.Println("[Agent] open 探针已挂载")
	}

	if a.cfg.Probe.Connect {
		l, err := link.Tracepoint("syscalls", "sys_enter_connect", collection.Programs["trace_connect"], nil)
		if err != nil {
			return links, fmt.Errorf("挂载 connect 探针失败: %w", err)
		}
		links = append(links, l)
		log.Println("[Agent] connect 探针已挂载")
	}

	return links, nil
}

// readEvents 读取 eBPF 事件
func (a *Agent) readEvents(ctx context.Context, reader *ringbuf.Reader) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := reader.Read()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("[Agent] 读取事件失败: %v", err)
			continue
		}

		// 解析事件类型
		if len(record.RawSample) < 4 {
			continue
		}

		eventType := binary.LittleEndian.Uint32(record.RawSample)
		switch eventType {
		case eventTypeExecve:
			a.handleExecveEvent(record.RawSample)
		case eventTypeOpen:
			a.handleOpenEvent(record.RawSample)
		case eventTypeConnect:
			a.handleConnectEvent(record.RawSample)
		}
	}
}

// handleExecveEvent 处理 execve 事件
func (a *Agent) handleExecveEvent(data []byte) {
	var bpfEvent bpfExecveEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &bpfEvent); err != nil {
		log.Printf("[Agent] 解析 execve 事件失败: %v", err)
		return
	}

	filename := trimNull(bpfEvent.Filename[:])
	args := trimNull(bpfEvent.Args[:])
	comm := trimNull(bpfEvent.Comm[:])

	// 规则匹配
	match := a.rules.MatchExecve(filename, args, comm)
	if match == nil {
		return
	}

	// 构建丰富事件
	enriched := &event.EnrichedEvent{
		EventType:     event.EventExecve,
		Timestamp:      time.Now(),
		PID:           bpfEvent.PID,
		PPID:          bpfEvent.PPID,
		Comm:          comm,
		Detail:        match.Detail,
		MatchedRule:   match.RuleName,
		Severity:      match.Severity,
		ActionNeeded:  match.Action != rules.ActionAlert,
	}

	// 解析 K8s 上下文
	a.enrichWithK8s(enriched, bpfEvent.PID, bpfEvent.CgroupID)

	// 发送事件
	select {
	case a.eventCh <- enriched:
	default:
		log.Printf("[Agent] 事件通道已满，丢弃事件")
	}
}

// handleOpenEvent 处理 open 事件
func (a *Agent) handleOpenEvent(data []byte) {
	var bpfEvent bpfOpenEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &bpfEvent); err != nil {
		log.Printf("[Agent] 解析 open 事件失败: %v", err)
		return
	}

	path := trimNull(bpfEvent.Path[:])
	comm := trimNull(bpfEvent.Comm[:])

	// 规则匹配
	match := a.rules.MatchOpen(path, comm)
	if match == nil {
		return
	}

	enriched := &event.EnrichedEvent{
		EventType:     event.EventOpen,
		Timestamp:      time.Now(),
		PID:           bpfEvent.PID,
		PPID:          bpfEvent.PPID,
		Comm:          comm,
		Detail:        match.Detail,
		MatchedRule:   match.RuleName,
		Severity:      match.Severity,
		ActionNeeded:  match.Action != rules.ActionAlert,
	}

	a.enrichWithK8s(enriched, bpfEvent.PID, bpfEvent.CgroupID)

	select {
	case a.eventCh <- enriched:
	default:
		log.Printf("[Agent] 事件通道已满，丢弃事件")
	}
}

// handleConnectEvent 处理 connect 事件
func (a *Agent) handleConnectEvent(data []byte) {
	var bpfEvent bpfConnectEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &bpfEvent); err != nil {
		log.Printf("[Agent] 解析 connect 事件失败: %v", err)
		return
	}

	comm := trimNull(bpfEvent.Comm[:])
	ip := net.IP(bpfEvent.IP[:])
	if bpfEvent.IPVersion == 4 {
		ip = net.IP(bpfEvent.IP[:4])
	}

	// 端口从网络字节序（大端）转换为主机字节序
	// bpf_probe_read_user 直接拷贝了 sin_port 的原始字节，
	// binary.Read 用 LittleEndian 读取后需要交换字节序
	port := (bpfEvent.Port >> 8) | (bpfEvent.Port << 8)

	// 规则匹配
	match := a.rules.MatchConnect(ip, port, comm)
	if match == nil {
		return
	}

	enriched := &event.EnrichedEvent{
		EventType:     event.EventConnect,
		Timestamp:      time.Now(),
		PID:           bpfEvent.PID,
		PPID:          bpfEvent.PPID,
		Comm:          comm,
		Detail:        match.Detail,
		MatchedRule:   match.RuleName,
		Severity:      match.Severity,
		ActionNeeded:  match.Action != rules.ActionAlert,
	}

	a.enrichWithK8s(enriched, bpfEvent.PID, bpfEvent.CgroupID)

	select {
	case a.eventCh <- enriched:
	default:
		log.Printf("[Agent] 事件通道已满，丢弃事件")
	}
}

// enrichWithK8s 用 K8s 上下文丰富事件
func (a *Agent) enrichWithK8s(e *event.EnrichedEvent, pid uint32, cgroupID uint32) {
	if a.k8s == nil {
		return
	}

	// 先尝试通过 PID 解析
	if pod := a.k8s.ResolveByPID(pid); pod != nil {
		e.Namespace = pod.Namespace
		e.PodName = pod.Name
		e.Container = pod.Container
		return
	}

	// 再尝试通过 cgroup 解析
	if pod := a.k8s.ResolveByCgroup(cgroupID); pod != nil {
		e.Namespace = pod.Namespace
		e.PodName = pod.Name
		e.Container = pod.Container
	}
}

// processEvents 处理事件
func (a *Agent) processEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-a.eventCh:
			// 打印事件
			log.Printf("[Event] %s", e.Format())

			// 如果需要响应，生成告警
			if e.ActionNeeded && a.cfg.Response.Enabled {
				alert := &event.Alert{
					Timestamp: e.Timestamp,
					EventType: e.EventType,
					Namespace: e.Namespace,
					PodName:   e.PodName,
					Container: e.Container,
					Detail:    e.Detail,
					Rule:      e.MatchedRule,
					Severity:  e.Severity,
				}
				select {
				case a.alertCh <- alert:
				default:
					log.Printf("[Agent] 告警通道已满，丢弃告警")
				}
			}
		}
	}
}

// processAlerts 处理告警并执行响应
func (a *Agent) processAlerts(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case alert := <-a.alertCh:
			// 确定响应动作
			action := a.determineAction(alert.Severity)
			alert.Action = string(action)

			// 打印告警
			log.Printf("[Alert] %s", alert.Format())

			// 执行响应
			if a.k8s != nil && alert.Namespace != "" && alert.PodName != "" {
				a.executeResponse(ctx, alert, action)
			}
		}
	}
}

// determineAction 根据严重等级确定动作
func (a *Agent) determineAction(severity event.SecurityLevel) rules.Action {
	switch severity {
	case event.LevelCritical:
		return rules.Action(a.cfg.Response.HighSeverityAction)
	case event.LevelHigh:
		return rules.Action(a.cfg.Response.DefaultAction)
	default:
		return rules.ActionAlert
	}
}

// executeResponse 执行响应动作
func (a *Agent) executeResponse(ctx context.Context, alert *event.Alert, action rules.Action) {
	switch action {
	case rules.ActionLabel:
		err := a.k8s.IsolatePod(ctx, alert.Namespace, alert.PodName,
			a.cfg.Response.IsolationLabelKey, a.cfg.Response.IsolationLabelValue)
		if err != nil {
			log.Printf("[Agent] 隔离 Pod 失败: %v", err)
		}
	case rules.ActionKill:
		err := a.k8s.KillPod(ctx, alert.Namespace, alert.PodName)
		if err != nil {
			log.Printf("[Agent] 终止 Pod 失败: %v", err)
		}
	case rules.ActionNetworkPolicy:
		// 打标签触发 NetworkPolicy
		err := a.k8s.IsolatePod(ctx, alert.Namespace, alert.PodName,
			a.cfg.Response.IsolationLabelKey, a.cfg.Response.IsolationLabelValue)
		if err != nil {
			log.Printf("[Agent] 隔离 Pod 失败: %v", err)
		}
		log.Printf("[Agent] 已标记 Pod %s/%s 触发 NetworkPolicy 隔离", alert.Namespace, alert.PodName)
	case rules.ActionAlert:
		// 仅告警，不执行动作
	default:
		log.Printf("[Agent] 未知响应动作: %s", action)
	}
}

// trimNull 去除字符串中的 null 字节
func trimNull(b []byte) string {
	return string(bytes.TrimRight(b, "\x00"))
}

// logLevelWeights 日志级别权重
var logLevelWeights = map[string]int{
	"debug": 0,
	"info":  1,
	"warn":  2,
	"error": 3,
}

// shouldLog 判断当前日志级别是否应该输出
func (a *Agent) shouldLog(level string) bool {
	configLevel, ok1 := logLevelWeights[a.cfg.LogLevel]
	msgLevel, ok2 := logLevelWeights[level]
	if !ok1 || !ok2 {
		return true
	}
	return msgLevel >= configLevel
}

// setupLogging 根据配置设置日志级别
func (a *Agent) setupLogging() {
	switch a.cfg.LogLevel {
	case "debug":
		log.SetFlags(log.LstdFlags | log.Lshortfile)
		log.Println("[Agent] 日志级别: debug")
	case "warn", "error":
		log.SetFlags(log.LstdFlags)
	default:
		log.SetFlags(log.LstdFlags)
	}
}

// watchRulesReload 监听 SIGHUP 信号热重载规则
func (a *Agent) watchRulesReload(ctx context.Context) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)

	for {
		select {
		case <-ctx.Done():
			signal.Stop(sigCh)
			return
		case <-sigCh:
			if a.cfg.Rules.RulesFile == "" {
				continue
			}
			log.Printf("[Agent] 收到 SIGHUP 信号，正在重载规则: %s", a.cfg.Rules.RulesFile)
			if err := a.rules.ReloadRules(a.cfg.Rules.RulesFile); err != nil {
				log.Printf("[Agent] 重载规则失败: %v", err)
			} else {
				log.Printf("[Agent] 规则重载成功，当前 %d 条规则", a.rules.GetRuleCount())
			}
		}
	}
}

// WaitForSignal 等待退出信号
func WaitForSignal() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		cancel()
	}()

	return ctx
}
