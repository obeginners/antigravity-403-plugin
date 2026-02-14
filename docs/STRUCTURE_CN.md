# 项目结构说明

[English](STRUCTURE.md) | 中文

本仓库在高层目录上对齐 `CLIProxyAPI-main`，便于上手与迁移：

- `cmd/`：入口程序
- `internal/`：内部实现
- `docs/`：项目文档
- `examples/`：示例
- `.github/workflows/`：CI

该插件保持为独立可执行程序，不需要修改 CLIProxyAPI 本体源码。

`auths/`、`logs/` 这类运行时目录默认不纳入 Git 跟踪，请在本地（或部署环境）按需创建。
