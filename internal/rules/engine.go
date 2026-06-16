package rules

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/shuhuNB515/KubeVigil/internal/event"
	"gopkg.in/yaml.v3"
)

// Action 响应动作
type Action string

const (
	ActionAlert         Action = "alert"
	ActionLabel         Action = "label"
	ActionKill          Action = "kill"
	ActionNetworkPolicy Action = "network_policy"
)

// Rule 规则定义
type Rule struct {
	// 规则名称
	Name string `yaml:"name"`
	// 规则描述
	Description string `yaml:"description"`
	// 事件类型: execve, open, connect
	EventType string `yaml:"eventType"`
	// 严重等级: info, low, medium, high, critical
	Severity string `yaml:"severity"`
	// 响应动作
	Action string `yaml:"action"`
	// 是否启用
	Enabled bool `yaml:"enabled"`

	// execve 规则
	Execve *ExecveRule `yaml:"execve,omitempty"`

	// open 规则
	Open *OpenRule `yaml:"open,omitempty"`

	// connect 规则
	Connect *ConnectRule `yaml:"connect,omitempty"`
}

// ExecveRule execve 规则
type ExecveRule struct {
	// 黑名单：匹配到的进程名视为异常
	BlockedProcesses []string `yaml:"blockedProcesses"`
	// 白名单：不匹配的进程名视为异常（仅允许这些进程）
	AllowedProcesses []string `yaml:"allowedProcesses"`
	// 黑名单参数模式
	BlockedArgs []string `yaml:"blockedArgs"`
}

// OpenRule open 规则
type OpenRule struct {
	// 敏感路径列表
	SensitivePaths []string `yaml:"sensitivePaths"`
	// 排除的进程
	ExcludeProcesses []string `yaml:"excludeProcesses"`
}

// ConnectRule connect 规则
type ConnectRule struct {
	// 黑名单 IP/CIDR
	BlockedCIDRs []string `yaml:"blockedCIDRs"`
	// 黑名单端口
	BlockedPorts []uint16 `yaml:"blockedPorts"`
	// 解析后的 CIDR 网络
	blockedNets []*net.IPNet
}

// Ruleset 规则集
type Ruleset struct {
	Rules []Rule `yaml:"rules"`
}

// Engine 规则引擎
type Engine struct {
	rules *Ruleset
}

// NewEngine 创建规则引擎
func NewEngine() *Engine {
	return &Engine{
		rules: &Ruleset{Rules: []Rule{}},
	}
}

// LoadRules 从文件加载规则
func (e *Engine) LoadRules(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取规则文件失败: %w", err)
	}

	var rs Ruleset
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return fmt.Errorf("解析规则文件失败: %w", err)
	}

	// 预处理 connect 规则的 CIDR
	for i := range rs.Rules {
		if rs.Rules[i].Connect != nil {
			if err := e.parseCIDRs(&rs.Rules[i]); err != nil {
				return fmt.Errorf("规则 %q CIDR 解析失败: %w", rs.Rules[i].Name, err)
			}
		}
	}

	e.rules = &rs
	return nil
}

// parseCIDRs 解析 CIDR
func (e *Engine) parseCIDRs(rule *Rule) error {
	rule.Connect.blockedNets = make([]*net.IPNet, 0, len(rule.Connect.BlockedCIDRs))
	for _, cidr := range rule.Connect.BlockedCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		rule.Connect.blockedNets = append(rule.Connect.blockedNets, ipNet)
	}
	return nil
}

// LoadDefaultRules 加载默认规则
func (e *Engine) LoadDefaultRules() {
	e.rules = DefaultRuleset()
}

// MatchExecve 匹配 execve 事件
func (e *Engine) MatchExecve(filename string, args string, comm string) *MatchResult {
	for i := range e.rules.Rules {
		rule := &e.rules.Rules[i]
		if !rule.Enabled || rule.EventType != "execve" || rule.Execve == nil {
			continue
		}

		matched := false
		detail := ""

		// 黑名单进程
		for _, blocked := range rule.Execve.BlockedProcesses {
			if matchProcess(filename, blocked) {
				matched = true
				detail = fmt.Sprintf("异常执行了黑名单进程: %s", filename)
				break
			}
		}

		// 白名单检查（如果定义了白名单，不在白名单中的进程都视为异常）
		if !matched && len(rule.Execve.AllowedProcesses) > 0 {
			found := false
			for _, allowed := range rule.Execve.AllowedProcesses {
				if matchProcess(filename, allowed) {
					found = true
					break
				}
			}
			if !found {
				matched = true
				detail = fmt.Sprintf("执行了非白名单进程: %s", filename)
			}
		}

		// 黑名单参数
		if !matched {
			for _, blockedArg := range rule.Execve.BlockedArgs {
				if strings.Contains(strings.ToLower(args), strings.ToLower(blockedArg)) {
					matched = true
					detail = fmt.Sprintf("进程 %s 包含可疑参数: %s", filename, args)
					break
				}
			}
		}

		if matched {
			return &MatchResult{
				RuleName:    rule.Name,
				Severity:    event.SecurityLevel(rule.Severity),
				Action:      Action(rule.Action),
				Detail:      detail,
				Description: rule.Description,
			}
		}
	}
	return nil
}

// MatchOpen 匹配 open 事件
func (e *Engine) MatchOpen(path string, comm string) *MatchResult {
	for i := range e.rules.Rules {
		rule := &e.rules.Rules[i]
		if !rule.Enabled || rule.EventType != "open" || rule.Open == nil {
			continue
		}

		// 检查进程排除
		excluded := false
		for _, exc := range rule.Open.ExcludeProcesses {
			if matchProcess(comm, exc) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}

		// 检查敏感路径
		for _, sensitive := range rule.Open.SensitivePaths {
			if strings.HasPrefix(path, sensitive) || matchGlob(path, sensitive) {
				return &MatchResult{
					RuleName:    rule.Name,
					Severity:    event.SecurityLevel(rule.Severity),
					Action:      Action(rule.Action),
					Detail:      fmt.Sprintf("进程 %s 访问了敏感路径: %s", comm, path),
					Description: rule.Description,
				}
			}
		}
	}
	return nil
}

// MatchConnect 匹配 connect 事件
func (e *Engine) MatchConnect(ip net.IP, port uint16, comm string) *MatchResult {
	for i := range e.rules.Rules {
		rule := &e.rules.Rules[i]
		if !rule.Enabled || rule.EventType != "connect" || rule.Connect == nil {
			continue
		}

		// 检查黑名单端口
		for _, blockedPort := range rule.Connect.BlockedPorts {
			if port == blockedPort {
				return &MatchResult{
					RuleName:    rule.Name,
					Severity:    event.SecurityLevel(rule.Severity),
					Action:      Action(rule.Action),
					Detail:      fmt.Sprintf("进程 %s 连接到可疑端口: %d", comm, port),
					Description: rule.Description,
				}
			}
		}

		// 检查黑名单 CIDR
		for _, ipNet := range rule.Connect.blockedNets {
			if ipNet.Contains(ip) {
				return &MatchResult{
					RuleName:    rule.Name,
					Severity:    event.SecurityLevel(rule.Severity),
					Action:      Action(rule.Action),
					Detail:      fmt.Sprintf("进程 %s 连接到可疑 IP: %s", comm, ip.String()),
					Description: rule.Description,
				}
			}
		}
	}
	return nil
}

// MatchResult 匹配结果
type MatchResult struct {
	RuleName    string
	Severity    event.SecurityLevel
	Action      Action
	Detail      string
	Description string
}

// matchProcess 匹配进程名
func matchProcess(filename, pattern string) bool {
	// 精确匹配
	if filename == pattern {
		return true
	}
	// basename 匹配
	if filepath.Base(filename) == pattern {
		return true
	}
	// glob 匹配
	matched, _ := filepath.Match(pattern, filepath.Base(filename))
	return matched
}

// matchGlob 简单的 glob 匹配
func matchGlob(path, pattern string) bool {
	matched, _ := filepath.Match(pattern, path)
	return matched
}

// DefaultRuleset 返回默认规则集
func DefaultRuleset() *Ruleset {
	return &Ruleset{
		Rules: []Rule{
			// execve 规则
			{
				Name:        "reverse-shell-detected",
				Description: "检测容器内可能的反弹 Shell 行为",
				EventType:   "execve",
				Severity:    "critical",
				Action:      "kill",
				Enabled:     true,
				Execve: &ExecveRule{
					BlockedProcesses: []string{"/bin/bash", "/bin/sh", "bash", "sh", "nc", "ncat", "socat"},
					BlockedArgs:      []string{"-e /bin/", "-c bash", "reverse", "/dev/tcp/"},
				},
			},
			{
				Name:        "suspicious-download",
				Description: "检测容器内可疑的文件下载行为",
				EventType:   "execve",
				Severity:    "high",
				Action:      "label",
				Enabled:     true,
				Execve: &ExecveRule{
					BlockedProcesses: []string{"wget", "curl"},
					BlockedArgs:      []string{"| bash", "| sh", "| /bin/"},
				},
			},
			{
				Name:        "crypto-mining",
				Description: "检测容器内可能的加密货币挖矿行为",
				EventType:   "execve",
				Severity:    "critical",
				Action:      "kill",
				Enabled:     true,
				Execve: &ExecveRule{
					BlockedProcesses: []string{"xmrig", "minerd", "cpuminer", "cryptonight"},
				},
			},
			// open 规则
			{
				Name:        "sensitive-file-access",
				Description: "检测对敏感文件的非授权访问",
				EventType:   "open",
				Severity:    "high",
				Action:      "label",
				Enabled:     true,
				Open: &OpenRule{
					SensitivePaths: []string{
						"/etc/shadow",
						"/etc/passwd",
						"/var/run/secrets/kubernetes.io/",
						"/etc/kubernetes/",
						"/root/.ssh/",
						"/root/.kube/",
					},
					ExcludeProcesses: []string{"cat", "less", "more", "head", "tail"},
				},
			},
			// connect 规则
			{
				Name:        "c2-communication",
				Description: "检测与已知 C2 服务器的通信",
				EventType:   "connect",
				Severity:    "critical",
				Action:      "network_policy",
				Enabled:     true,
				Connect: &ConnectRule{
					BlockedCIDRs: []string{
						"0.0.0.0/0", // 占位，实际使用时替换为已知恶意 IP 段
					},
					BlockedPorts: []uint16{4444, 5555, 6666, 7777, 8888},
				},
			},
		},
	}
}
