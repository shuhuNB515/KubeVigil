package main

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"

	"github.com/shuhuNB515/KubeVigil/internal/agent"
	"github.com/shuhuNB515/KubeVigil/internal/config"
)

var (
	version    = "0.1.0"
	configPath string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "kubevigil",
		Short: "KubeVigil - K8s 运行时安全守夜人",
		Long: `KubeVigil (K8s 守夜人) - 基于 eBPF 的 Kubernetes 运行时威胁检测与响应工具

利用 eBPF 技术在内核态监控系统调用，实时检测容器内的异常行为，
并自动执行隔离、终止等响应策略。`,
		RunE: runAgent,
	}

	rootCmd.Flags().StringVarP(&configPath, "config", "c", "", "配置文件路径")

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "显示版本信息",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("KubeVigil v%s\n", version)
		},
	}

	rootCmd.AddCommand(versionCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runAgent(cmd *cobra.Command, args []string) error {
	printBanner()

	// 加载配置
	var cfg *config.Config
	if configPath != "" {
		var err error
		cfg, err = config.LoadConfig(configPath)
		if err != nil {
			return fmt.Errorf("加载配置失败: %w", err)
		}
		log.Printf("[Main] 已加载配置: %s", configPath)
	} else {
		cfg = config.DefaultConfig()
		log.Println("[Main] 使用默认配置")
	}

	// 创建 Agent
	a, err := agent.New(cfg)
	if err != nil {
		return fmt.Errorf("创建 Agent 失败: %w", err)
	}

	// 等待退出信号
	ctx := agent.WaitForSignal()

	// 运行 Agent
	return a.Run(ctx)
}

func printBanner() {
	banner := `
  _  __      _    _  _   ___  _  _  ___  _   _  _   _  _    ___  ___
 | |/ /     | |  | || | / _ \| || |/ __|| | | || \ | || |  / __||_ _|
 | ' /  ____| |  | || || (_) | || |\__ \| |_| ||  \| || |_| (__  | |
 |_|\_\|____|_|  |_||_| \___/|_||_||___/ \___/ |_|\__|\___|\___||___|

                          K8s Runtime Security Guard
                          Powered by eBPF
`
	fmt.Println(banner)
}
