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
	if cfg.RulesPath != "/etc/kubevigil/rules.yaml" {
		t.Errorf("默认规则路径不正确: %s", cfg.RulesPath)
	}
	if cfg.BPFObjPath != "/opt/kubevigil/probes.o" {
		t.Errorf("默认 BPF 对象路径不正确: %s", cfg.BPFObjPath)
	}
}

func TestLoadConfig(t *testing.T) {
	// 创建临时配置文件
	content := `
logLevel: debug
rulesPath: /tmp/rules.yaml
bpfObjPath: /tmp/probes.o
kubernetes:
  inCluster: true
  nodeName: test-node
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
	if cfg.Kubernetes.NodeName != "test-node" {
		t.Errorf("节点名应为 test-node，实际 %s", cfg.Kubernetes.NodeName)
	}
}

func TestLoadConfig_NotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Error("加载不存在的配置文件应返回错误")
	}
}
