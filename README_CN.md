# antigravity-403-plugin

[English](README.md) | 中文

这是一个独立于 CLIProxyAPI 本体的 Antigravity 反代插件，主要用于处理 `/v1internal*` 路由并提升 403 场景下的稳定性。

目标是：不改本体源码、可单独发布、可直接 Docker 化部署。

## 依赖关系与启动顺序

- 本插件不是独立模型服务，必须配合 CLIProxyAPI 本体使用。
- 启动顺序：先启动 CLIProxyAPI 本体，再启动本插件。
- 停止顺序建议：先停插件，再停 CLIProxyAPI 本体。

## 功能

- 针对 Antigravity 路径的反向代理（支持 uTLS 指纹）
- 支持 Antigravity 上游回退链路
- 可选凭证 `base_url` 注入与退出恢复
- 可选启动自检（上游 + `/v1/models`）
- 文件日志与可选日志清理
- 提供 Dockerfile + docker-compose

## 403 现象参考

这是官方 Antigravity 返回 403 时常见的提示文案：

```text
Verification required
Please verify your account to continue using Antigravity. Learn more
Dismiss
Complete verification
```

官方 403 API 返回：

```json
{
  "error": {
    "code": 403,
    "message": "Verify your account to continue.",
    "status": "PERMISSION_DENIED",
    "details": [
      {
        "@type": "type.googleapis.com/google.rpc.ErrorInfo",
        "reason": "VALIDATION_REQUIRED",
        "domain": "cloudcode-pa.googleapis.com",
        "metadata": {
          "validation_error_message": "Verify your account to continue.",
          "validation_url_link_text": "Verify your account",
          "validation_url": "https://accounts.google.com/signin/continue?...<REDACTED>...",
          "validation_learn_more_link_text": "Learn more",
          "validation_learn_more_url": "https://support.google.com/accounts?p=al_alert"
        }
      }
    ]
  }
}
```

## 仓库结构

```text
.
├─ .github/workflows/        # CI 工作流
├─ cmd/plugin/               # 程序入口
├─ docs/                     # 文档
├─ examples/                 # 示例
├─ internal/proxy/           # 代理核心实现
├─ .dockerignore
├─ .goreleaser.yml
├─ config.example.yaml
├─ docker-build.ps1
├─ docker-build.sh
├─ docker-compose.yml
├─ Dockerfile
├─ README.md
├─ README_CN.md
```

## 配置准备 EXE 与 Docker 通用

先复制配置文件：

```bash
cp config.example.yaml config.yaml
```

## 配置优先级

参数生效顺序：

`命令行参数 > 环境变量 > config.yaml > 程序默认值`

## 常见配置项说明

以下配置项用于说明含义，按需修改，不是都要改。

- `cli-upstream`
说明：插件要转发到哪个 CLI 本体地址。
常见值：`http://127.0.0.1:8317`（本地）或 `http://host.docker.internal:8317`（容器访问宿主机）。

- `auth-dir`
说明：插件读取/注入凭证文件的目录。
关键点：要和 CLI 本体实际使用的凭证目录指向同一份数据。

- `inject-auth-base-url`
说明：是否自动写入凭证 `base_url` 到插件地址。
建议：保持 `true`。

- `force-auth-refresh`
说明：是否强制刷新凭证文件触发热重载。
建议：默认留空或 false，需要时再开。

- `log-cleanup-interval`
说明：日志清理周期。
建议：默认留空，要清理可填 `30d`。

- `self-check` / `self-check-api-key`
说明：启动时健康检查与 `/v1/models` 检查。
建议：`self-check: true`，`self-check-api-key` 可填本体可用 key。

## 部署方式总览

- Windows EXE 版本 本地运行
- 服务器 Docker 版本

## Windows EXE 版本 本地运行

按下面步骤执行：

1. 下载并解压 Release 压缩包。
2. 在解压目录把 `config.example.yaml` 复制为 `config.yaml` 并按需修改。
3. 先启动 CLIProxyAPI 本体。
4. 再启动插件：

```powershell
.\antigravity-403-plugin.exe
```

补充：

- 默认不需要编译。
- 默认不需要 `-config` 参数，程序会自动读取 `config.yaml`。
- 只有配置文件名或路径不同，才需要 `-config`。

可选：从源码编译后运行：

```powershell
go build -o antigravity-403-plugin.exe ./cmd/plugin
Copy-Item .\config.example.yaml .\config.yaml
.\antigravity-403-plugin.exe
```

## 服务器 Docker 版本

先部署 CLI 本体 官方流程：

```bash
git clone https://github.com/router-for-me/CLIProxyAPI.git
cd CLIProxyAPI
cp config.example.yaml config.yaml
docker compose up -d
```

再部署插件：

1. 获取插件源码：

```bash
git clone https://github.com/obeginners/antigravity-403-plugin.git
cd antigravity-403-plugin
```

2. 准备插件配置：

```bash
cp config.example.yaml config.yaml
```

3. 修改 `config.yaml`（官方部署可直接执行；非官方部署请替换为你的实际值）
   - 需要按实际替换的项：`auth-dir`、`inject-base-url`、`cli-upstream`。

```bash
sed -i 's#^auth-dir:.*#auth-dir: "/app/auths"#' config.yaml
```

```bash
sed -i 's#^inject-base-url:.*#inject-base-url: "http://172.17.0.1:9813"#' config.yaml
```

```bash
sed -i 's#^cli-upstream:.*#cli-upstream: "http://host.docker.internal:8317"#' config.yaml
```

4. 仅当你的 auth 目录不是官方默认路径时，再改 `docker-compose.yml`
   - 官方默认宿主机路径：`/root/CLIProxyAPI/auths`

```bash
# 把 /你的实际auth目录 改成你的真实路径
sed -i 's#^\\s*- .*:/app/auths#      - /你的实际auth目录:/app/auths#' docker-compose.yml
```

5. 启动插件：

```bash
docker compose up -d
```

6. 查看日志：

```bash
docker compose logs -f antigravity-403-plugin
```

7. 停止插件：

```bash
docker compose down
```

登录/凭证说明：

- 插件本身不提供登录命令。
- 需要在 CLI 本体中完成登录，并让插件读取同一份 `auths`。
- 插件运行时会向凭证注入 `base_url`；正常退出后会自动清除插件注入的 `base_url`。
- CLI 容器登录示例：

```bash
docker compose exec cli-proxy-api /CLIProxyAPI/CLIProxyAPI -no-browser --antigravity-login
```

## 许可证

MIT
