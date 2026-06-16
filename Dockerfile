# ==================== 构建阶段 ====================
FROM golang:1.21-bookworm AS builder

# 安装 eBPF 依赖
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 先复制 go.mod/go.sum 以利用 Docker 缓存
COPY go.mod go.sum ./
RUN go mod download

# 复制源代码
COPY . .

# 编译 eBPF 程序为 BPF CO-RE 目标文件
RUN clang -g -O2 -target bpf \
    -D__TARGET_ARCH_x86 \
    -I/usr/include/$(uname -m)-linux-gnu \
    -c bpf/probes/probes.bpf.c \
    -o bpf/probes.o

# 编译 Go 程序
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o kubevigil ./cmd/kubevigil

# ==================== 运行阶段 ====================
FROM gcr.io/distroless/static:nonroot

WORKDIR /

# 从构建阶段复制二进制文件和 eBPF 程序
COPY --from=builder /app/kubevigil /usr/local/bin/kubevigil
COPY --from=builder /app/bpf/probes.o /etc/kubevigil/probes.o
COPY --from=builder /app/configs/rules.yaml /etc/kubevigil/rules.yaml

ENTRYPOINT ["kubevigil"]
CMD ["-c", "/etc/kubevigil/rules.yaml"]
