package event

import (
	"fmt"
	"net"
	"time"
)

// EventType 事件类型
type EventType int

const (
	EventExecve  EventType = 1
	EventOpen    EventType = 2
	EventConnect EventType = 3
)

func (t EventType) String() string {
	switch t {
	case EventExecve:
		return "EXECVE"
	case EventOpen:
		return "OPEN"
	case EventConnect:
		return "CONNECT"
	default:
		return "UNKNOWN"
	}
}

// SecurityLevel 安全等级
type SecurityLevel string

const (
	LevelInfo     SecurityLevel = "info"
	LevelLow      SecurityLevel = "low"
	LevelMedium   SecurityLevel = "medium"
	LevelHigh     SecurityLevel = "high"
	LevelCritical SecurityLevel = "critical"
)

// RawEvent 从 eBPF Ring Buffer 读取的原始事件
type RawEvent struct {
	Type      EventType
	PID       uint32
	PPID      uint32
	TID       uint32
	Timestamp uint64
	Comm      string
	CgroupID  uint32
}

// ExecveEvent execve 系统调用事件
type ExecveEvent struct {
	RawEvent
	Filename string
	Args     string
}

// OpenEvent open 系统调用事件
type OpenEvent struct {
	RawEvent
	Path  string
	Flags int32
}

// ConnectEvent connect 系统调用事件
type ConnectEvent struct {
	RawEvent
	IPVersion uint8
	IP        net.IP
	Port      uint16
}

// EnrichedEvent 经过 K8s 上下文丰富后的事件
type EnrichedEvent struct {
	// 原始事件
	EventType EventType
	Timestamp time.Time
	PID       uint32
	Comm      string

	// K8s 上下文
	Namespace string
	PodName   string
	Container string

	// 事件详情 (根据类型不同)
	Detail string

	// 规则匹配结果
	MatchedRule  string
	Severity     SecurityLevel
	ActionNeeded bool
}

// Format 格式化输出事件
func (e *EnrichedEvent) Format() string {
	timestamp := e.Timestamp.Format("15:04:05")
	if e.Namespace != "" {
		return fmt.Sprintf("[%s] [%s] Namespace: %s, Pod: %s, PID: %d, Comm: %s, %s (Rule: %s, Severity: %s)",
			timestamp, e.EventType, e.Namespace, e.PodName, e.PID, e.Comm, e.Detail, e.MatchedRule, e.Severity)
	}
	return fmt.Sprintf("[%s] [%s] PID: %d, Comm: %s, %s (Rule: %s, Severity: %s)",
		timestamp, e.EventType, e.PID, e.Comm, e.Detail, e.MatchedRule, e.Severity)
}

// Alert 告警信息
type Alert struct {
	Timestamp time.Time
	EventType EventType
	Namespace string
	PodName   string
	Container string
	Detail    string
	Rule      string
	Severity  SecurityLevel
	Action    string
}

// Format 格式化告警
func (a *Alert) Format() string {
	timestamp := a.Timestamp.Format("2006-01-02 15:04:05")
	return fmt.Sprintf("[ALERT] [%s] %s | Namespace: %s, Pod: %s | %s | Rule: %s | Severity: %s | Action: %s",
		a.EventType, timestamp, a.Namespace, a.PodName, a.Detail, a.Rule, a.Severity, a.Action)
}
