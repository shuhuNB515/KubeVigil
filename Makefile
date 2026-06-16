.PHONY: all build bpf clean docker helm install test lint

# 变量
BINARY_NAME=kubevigil
VERSION?=0.1.0
IMAGE?=kubevigil/$(BINARY_NAME)
TAG?=$(VERSION)
ARCH?=amd64

# Go 参数
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# clang 参数
CLANG=clang
BPF_CFLAGS=-g -O2 -target bpf -D__TARGET_ARCH_x86

all: bpf build

## bpf: 编译 eBPF 探针
bpf:
	$(CLANG) $(BPF_CFLAGS) -c bpf/probes/probes.bpf.c -o bpf/probes.o
	@echo "[OK] eBPF 探针编译完成: bpf/probes.o"

## build: 编译 Go 二进制
build:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) $(GOBUILD) -ldflags="-s -w -X main.version=$(VERSION)" -o $(BINARY_NAME) ./cmd/kubevigil
	@echo "[OK] Go 二进制编译完成: $(BINARY_NAME)"

## build-local: 本地编译（不交叉编译）
build-local:
	CGO_ENABLED=0 $(GOBUILD) -ldflags="-s -w -X main.version=$(VERSION)" -o $(BINARY_NAME) ./cmd/kubevigil
	@echo "[OK] 本地编译完成: $(BINARY_NAME)"

## docker: 构建 Docker 镜像
docker:
	docker build -t $(IMAGE):$(TAG) -t $(IMAGE):latest .
	@echo "[OK] Docker 镜像构建完成: $(IMAGE):$(TAG)"

## docker-push: 推送 Docker 镜像
docker-push:
	docker push $(IMAGE):$(TAG)
	docker push $(IMAGE):latest
	@echo "[OK] Docker 镜像推送完成"

## helm: 打包 Helm Chart
helm:
	helm package charts/kubevigil --version=$(VERSION) --app-version=$(VERSION)
	@echo "[OK] Helm Chart 打包完成: kubevigil-$(VERSION).tgz"

## install: 使用 Helm 安装到集群
install: docker helm
	helm upgrade --install kubevigil ./charts/kubevigil \
		--namespace kubevigil --create-namespace \
		--set image.repository=$(IMAGE) \
		--set image.tag=$(TAG)
	@echo "[OK] KubeVigil 已安装到集群"

## uninstall: 卸载 KubeVigil
uninstall:
	helm uninstall kubevigil --namespace kubevigil
	@echo "[OK] KubeVigil 已从集群卸载"

## test: 运行测试
test:
	$(GOTEST) -v -race ./...

## lint: 代码检查
lint:
	golangci-lint run ./...

## tidy: 整理 Go 模块
tidy:
	$(GOMOD) tidy

## clean: 清理构建产物
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f bpf/probes.o
	rm -f kubevigil-*.tgz
	@echo "[OK] 清理完成"

## help: 显示帮助
help:
	@echo "KubeVigil Makefile 命令:"
	@echo ""
	@echo "  make bpf           - 编译 eBPF 探针"
	@echo "  make build         - 编译 Go 二进制"
	@echo "  make build-local   - 本地编译（不交叉编译）"
	@echo "  make docker        - 构建 Docker 镜像"
	@echo "  make docker-push   - 推送 Docker 镜像"
	@echo "  make helm          - 打包 Helm Chart"
	@echo "  make install       - 安装到 K8s 集群"
	@echo "  make uninstall     - 从集群卸载"
	@echo "  make test          - 运行测试"
	@echo "  make lint          - 代码检查"
	@echo "  make tidy          - 整理 Go 模块"
	@echo "  make clean         - 清理构建产物"
