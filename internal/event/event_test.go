package event

import (
	"strings"
	"testing"
)

func TestEventType_String(t *testing.T) {
	tests := []struct {
		et       EventType
		expected string
	}{
		{EventExecve, "EXECVE"},
		{EventOpen, "OPEN"},
		{EventConnect, "CONNECT"},
		{EventType(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		result := tt.et.String()
		if result != tt.expected {
			t.Errorf("EventType(%d).String() = %q, expected %q", tt.et, result, tt.expected)
		}
	}
}

func TestEnrichedEvent_Format(t *testing.T) {
	e := &EnrichedEvent{
		EventType:   EventExecve,
		PID:         1234,
		PPID:        1,
		Comm:        "nc",
		Namespace:   "default",
		PodName:     "nginx-xyz",
		Detail:      "异常执行了黑名单进程: nc",
		MatchedRule: "reverse-shell-detected",
		Severity:    LevelCritical,
	}

	result := e.Format()
	if !strings.Contains(result, "EXECVE") {
		t.Error("格式化输出应包含 EXECVE")
	}
	if !strings.Contains(result, "default") {
		t.Error("格式化输出应包含 Namespace")
	}
	if !strings.Contains(result, "nginx-xyz") {
		t.Error("格式化输出应包含 PodName")
	}
	if !strings.Contains(result, "reverse-shell-detected") {
		t.Error("格式化输出应包含规则名")
	}
}

func TestEnrichedEvent_FormatNoK8s(t *testing.T) {
	e := &EnrichedEvent{
		EventType:   EventOpen,
		PID:         5678,
		Comm:        "cat",
		Detail:      "访问了敏感路径",
		MatchedRule: "sensitive-file-access",
		Severity:    LevelHigh,
	}

	result := e.Format()
	if !strings.Contains(result, "PID: 5678") {
		t.Error("无 K8s 上下文时应显示 PID")
	}
}

func TestAlert_Format(t *testing.T) {
	a := &Alert{
		EventType: EventConnect,
		Namespace: "production",
		PodName:   "api-server",
		Detail:    "连接到可疑端口: 4444",
		Rule:      "c2-communication",
		Severity:  LevelCritical,
		Action:    "network_policy",
	}

	result := a.Format()
	if !strings.Contains(result, "[ALERT]") {
		t.Error("告警格式化输出应包含 [ALERT]")
	}
	if !strings.Contains(result, "c2-communication") {
		t.Error("告警格式化输出应包含规则名")
	}
	if !strings.Contains(result, "network_policy") {
		t.Error("告警格式化输出应包含响应动作")
	}
}
