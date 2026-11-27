package config

import (
	"os"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.LogLevel != "info" {
		t.Errorf("默认日志级别应为 info，实际 %s", cfg.LogLevel)
	}
	if cfg.Rules.RulesFile != "/etc/kubevigil/rules.yaml" {
		t.Errorf("默认规则路径不正确: %s", cfg.Rules.RulesFile)
	}
	if cfg.Probe.RingBufferSize != 16 {
		t.Errorf("默认 RingBufferSize 应为 16，实际 %d", cfg.Probe.RingBufferSize)
	}
	if cfg.Response.DefaultAction != "label" {
		t.Errorf("默认响应动作应为 label，实际 %s", cfg.Response.DefaultAction)
	}
}

func TestLoadConfig(t *testing.T) {
	content := `
logLevel: debug
probe:
  execve: true
  open: false
  connect: true
  ringBufferSize: 32
rules:
  rulesFile: /tmp/rules.yaml
response:
  enabled: true
  defaultAction: kill
`
	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	cfg, err := LoadConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	if cfg.LogLevel != "debug" {
		t.Errorf("日志级别应为 debug，实际 %s", cfg.LogLevel)
	}
	if cfg.Rules.RulesFile != "/tmp/rules.yaml" {
		t.Errorf("规则文件路径应为 /tmp/rules.yaml，实际 %s", cfg.Rules.RulesFile)
	}
	if cfg.Probe.RingBufferSize != 32 {
		t.Errorf("RingBufferSize 应为 32，实际 %d", cfg.Probe.RingBufferSize)
	}
	if cfg.Response.DefaultAction != "kill" {
		t.Errorf("默认响应动作应为 kill，实际 %s", cfg.Response.DefaultAction)
	}
}

func TestLoadConfig_NotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Error("加载不存在的配置文件应返回错误")
	}
}
