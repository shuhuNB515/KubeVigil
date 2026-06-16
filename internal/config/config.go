package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config KubeVigil 全局配置
type Config struct {
	// eBPF 探针配置
	Probe ProbeConfig `yaml:"probe"`
	// 规则配置
	Rules RulesConfig `yaml:"rules"`
	// K8s 响应配置
	Response ResponseConfig `yaml:"response"`
	// 日志级别: debug, info, warn, error
	LogLevel string `yaml:"logLevel"`
}

// ProbeConfig eBPF 探针配置
type ProbeConfig struct {
	// 是否启用 execve 监控
	Execve bool `yaml:"execve"`
	// 是否启用 open 监控
	Open bool `yaml:"open"`
	// 是否启用 connect 监控
	Connect bool `yaml:"connect"`
	// Ring Buffer 大小 (MB)
	RingBufferSize int `yaml:"ringBufferSize"`
}

// RulesConfig 规则配置
type RulesConfig struct {
	// 规则文件路径
	RulesFile string `yaml:"rulesFile"`
}

// ResponseConfig 响应配置
type ResponseConfig struct {
	// 是否启用自动响应
	Enabled bool `yaml:"enabled"`
	// 响应动作: label, kill, network_policy
	DefaultAction string `yaml:"defaultAction"`
	// 隔离标签 key
	IsolationLabelKey string `yaml:"isolationLabelKey"`
	// 隔离标签 value
	IsolationLabelValue string `yaml:"isolationLabelValue"`
	// 高危规则触发的动作
	HighSeverityAction string `yaml:"highSeverityAction"`
}

// DefaultConfig 返回默认配置
func DefaultConfig() *Config {
	return &Config{
		Probe: ProbeConfig{
			Execve:        true,
			Open:          true,
			Connect:       true,
			RingBufferSize: 16,
		},
		Rules: RulesConfig{
			RulesFile: "/etc/kubevigil/rules.yaml",
		},
		Response: ResponseConfig{
			Enabled:             true,
			DefaultAction:       "label",
			IsolationLabelKey:   "kubevigil.io/isolated",
			IsolationLabelValue: "true",
			HighSeverityAction:  "kill",
		},
		LogLevel: "info",
	}
}

// LoadConfig 从文件加载配置
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	// 处理相对路径
	if cfg.Rules.RulesFile != "" && !filepath.IsAbs(cfg.Rules.RulesFile) {
		cfg.Rules.RulesFile = filepath.Join(filepath.Dir(path), cfg.Rules.RulesFile)
	}

	return cfg, nil
}
