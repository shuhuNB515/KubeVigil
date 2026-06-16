# 贡献指南

感谢你对 KubeVigil 的关注！欢迎通过以下方式参与贡献。

## 开发环境要求

- Go 1.21+
- Linux 内核 5.8+（支持 BPF CO-RE）
- clang/llvm 15+（编译 eBPF 程序）
- Docker（构建镜像）
- kubectl + 一个可用的 K8s 集群（集成测试）
- Helm 3+（部署测试）

## 开发流程

1. Fork 本仓库
2. 创建特性分支：`git checkout -b feature/my-feature`
3. 提交更改：`git commit -m "feat: 添加新功能"`
4. 推送分支：`git push origin feature/my-feature`
5. 创建 Pull Request

## 提交规范

使用 [Conventional Commits](https://www.conventionalcommits.org/) 格式：

- `feat:` 新功能
- `fix:` 修复 Bug
- `docs:` 文档更新
- `test:` 测试相关
- `refactor:` 代码重构
- `chore:` 构建/工具变更

## 代码规范

- 遵循 [Effective Go](https://go.dev/doc/effective_go) 规范
- 新功能必须包含单元测试
- eBPF 代码需要添加注释说明探针用途
- 公共 API 需要添加 GoDoc 注释

## 测试

```bash
# 运行单元测试
make test

# 运行 eBPF 编译检查
make generate

# 构建镜像
make docker-build
```

## 报告 Bug

请通过 [GitHub Issues](https://github.com/shuhuNB515/KubeVigil/issues) 提交 Bug 报告，包含以下信息：

- K8s 版本和内核版本
- KubeVigil 版本
- 复现步骤
- 预期行为与实际行为
- 相关日志输出
