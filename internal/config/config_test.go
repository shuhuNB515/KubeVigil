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
		t.Errorf("默认 Ring Buffer 大小不正确: %d", cfg.Probe.RingBufferSize)
	}
}

func TestLoadConfig(t *testing.T) {
	// 创建临时配置文件
	content := `
logLevel: debug
rules:
  rulesFile: /tmp/rules.yaml
probe:
  ringBufferSize: 32
response:
  enabled: false
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
		t.Errorf("规则路径应为 /tmp/rules.yaml，实际 %s", cfg.Rules.RulesFile)
	}
	if cfg.Probe.RingBufferSize != 32 {
		t.Errorf("Ring Buffer 大小应为 32，实际 %d", cfg.Probe.RingBufferSize)
	}
	if cfg.Response.Enabled {
		t.Error("显式禁用自动响应时应覆盖默认值")
	}
}

func TestLoadConfig_NotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Error("加载不存在的配置文件应返回错误")
	}
}
