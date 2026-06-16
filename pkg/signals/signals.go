package signals

import (
	"os"
	"os/signal"
	"syscall"
)

// SetupSignalHandler 注册信号处理，返回一个 channel 在收到信号时关闭
func SetupSignalHandler() <-chan struct{} {
	stop := make(chan struct{})
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		close(stop)
		<-sigCh
		os.Exit(1)
	}()

	return stop
}
