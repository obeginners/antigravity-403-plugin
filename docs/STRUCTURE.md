# Project Structure Notes

English | [中文](STRUCTURE_CN.md)

This repository mirrors the high-level layout of `CLIProxyAPI-main` for easier onboarding:

- `cmd/` entry binaries
- `internal/` implementation details
- `docs/` documentation
- `examples/` runnable examples
- `.github/workflows/` CI

The plugin remains a standalone executable and does not require changes to CLIProxyAPI source code.

Runtime paths such as `auths/` and `logs/` are intentionally not tracked.
Create them locally when running with Docker Compose.
