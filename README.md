# antigravity-403-plugin

English | [中文](README_CN.md)

A standalone proxy plugin for CLIProxyAPI that targets Antigravity routes (`/v1internal*`) and helps stabilize 403-heavy environments.

It is designed to be external (no patching of CLIProxyAPI source code), easy to ship, and easy to run in both native and Docker setups.

## Dependency and Startup Order

- This plugin is not a standalone model service; it must run with CLIProxyAPI.
- Startup order: start CLIProxyAPI first, then start this plugin.
- Recommended stop order: stop this plugin first, then stop CLIProxyAPI.

## Features

- Reverse proxy for Antigravity endpoints with uTLS fingerprint support
- Upstream fallback chain for Antigravity domains
- Optional credential `base_url` injection and restore
- Optional startup self-check (`/v1/models` + upstream check)
- File logging with optional retention cleanup
- Docker-ready image and compose deployment

## 403 Symptom Reference

Typical official Antigravity 403 copy:

```text
Verification required
Please verify your account to continue using Antigravity. Learn more
Dismiss
Complete verification
```

Official 403 API response:

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

## Repository Structure

```text
.
- .github/workflows/        # CI workflow
- cmd/plugin/               # plugin entrypoint
- docs/                     # project docs
- examples/                 # runnable examples
- internal/proxy/           # proxy core implementation
- .dockerignore
- .goreleaser.yml
- config.example.yaml
- docker-build.ps1
- docker-build.sh
- docker-compose.yml
- Dockerfile
- README.md
- README_CN.md
```

## Config Basics for EXE and Docker

Prepare `config.yaml` first:

```bash
cp config.example.yaml config.yaml
```

## Config Priority

Runtime value resolution order:

`CLI flags > environment variables > config.yaml > built-in defaults`

## Common Config Keys Reference

These keys are references. Change only when needed.

- `cli-upstream`
Meaning: where plugin forwards requests to CLIProxyAPI.
Typical values: `http://127.0.0.1:8317` (local) or `http://host.docker.internal:8317` (container -> host).

- `auth-dir`
Meaning: credential directory used by plugin for read/inject.
Important: it must point to the same credential data used by CLIProxyAPI.

- `inject-auth-base-url`
Meaning: auto-inject credential `base_url` to plugin address.
Recommendation: keep `true`.

- `force-auth-refresh`
Meaning: force-refresh credential files to trigger hot reload.
Recommendation: keep empty or false unless needed.

- `log-cleanup-interval`
Meaning: log retention cleanup interval.
Recommendation: keep empty, or set `30d` if needed.

- `self-check` / `self-check-api-key`
Meaning: startup health/model checks.
Recommendation: keep `self-check: true`; set `self-check-api-key` when needed.

## Deployment Modes

- Windows EXE mode
- Server Docker mode

## Windows EXE Mode

Follow these steps:

1. Download and extract the Release zip.
2. Copy `config.example.yaml` to `config.yaml` and edit as needed.
3. Start CLIProxyAPI first.
4. Start plugin:

```powershell
.\antigravity-403-plugin.exe
```

Notes:

- Build is not required by default.
- `-config` is not required by default because program auto-loads `config.yaml`.
- Use `-config` only when config file name/path is different.

Optional: build from source:

```powershell
go build -o antigravity-403-plugin.exe ./cmd/plugin
Copy-Item .\config.example.yaml .\config.yaml
.\antigravity-403-plugin.exe
```

## Server Docker Mode

Deploy CLIProxyAPI first with official flow:

```bash
git clone https://github.com/router-for-me/CLIProxyAPI.git
cd CLIProxyAPI
cp config.example.yaml config.yaml
docker compose up -d
```

Then deploy plugin:

1. Get plugin source:

```bash
git clone https://github.com/obeginners/antigravity-403-plugin.git
cd antigravity-403-plugin
```

2. Prepare plugin config:

```bash
cp config.example.yaml config.yaml
```

3. For official Docker deployment, you must first update two keys in `config.yaml`:
   - `auth-dir: "/app/auths"`
   - `inject-base-url: "http://172.17.0.1:9813"`

4. `docker-compose.yml` already defaults to the official path: `/root/CLIProxyAPI/auths:/app/auths`.

5. For non-default deployments, additionally adjust (`PLUGIN_AUTH_PATH`, `cli-upstream`, `listen`).
   - In `docker-compose.yml` / `.env`, set `PLUGIN_AUTH_PATH` to your actual auth directory.
   - In `config.yaml`, set `cli-upstream` to: `http://host.docker.internal:8317`

6. Start plugin:

```bash
docker compose up -d
```

7. View logs:

```bash
docker compose logs -f antigravity-403-plugin
```

8. Stop plugin:

```bash
docker compose down
```

Login/auth note:

- This plugin does not provide login commands.
- Complete login in CLIProxyAPI and let plugin read the same `auths` data.
- CLI container login example:

```bash
docker compose exec cli-proxy-api /CLIProxyAPI/CLIProxyAPI -no-browser --antigravity-login
```

## License

MIT
