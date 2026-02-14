# docker-build.ps1 - Windows PowerShell helper
#
# This script aligns with CLIProxyAPI's interactive Docker flow.
# 1) Run with pre-built image (recommended)
# 2) Build local image from source and run

$ErrorActionPreference = "Stop"

function Ensure-RuntimeFiles {
  if (-not (Test-Path -LiteralPath "config.yaml")) {
    if (Test-Path -LiteralPath "config.example.yaml") {
      Copy-Item -LiteralPath "config.example.yaml" -Destination "config.yaml" -Force
      Write-Host "Created config.yaml from config.example.yaml"
    } else {
      Write-Warning "config.example.yaml not found. Please create config.yaml manually."
    }
  }

  foreach ($dir in @("auths", "logs")) {
    if (-not (Test-Path -LiteralPath $dir)) {
      New-Item -ItemType Directory -Path $dir | Out-Null
      Write-Host "Created directory: $dir"
    }
  }
}

function Resolve-VersionInfo {
  $version = "dev"
  $commit = "none"
  $buildDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

  if (Get-Command git -ErrorAction SilentlyContinue) {
    try { $version = (git describe --tags --always --dirty).Trim() } catch {}
    try { $commit = (git rev-parse --short HEAD).Trim() } catch {}
  }

  return @{ VERSION = $version; COMMIT = $commit; BUILD_DATE = $buildDate }
}

Write-Host "Please select an option:"
Write-Host "1) Run using Pre-built Image (Recommended)"
Write-Host "2) Build from Source and Run (For Developers)"
$choice = Read-Host -Prompt "Enter choice [1-2]"

Ensure-RuntimeFiles

switch ($choice) {
  "1" {
    Write-Host "--- Running with Pre-built Image ---"
    docker compose up -d --remove-orphans --no-build
    Write-Host "Services are starting from remote image."
    Write-Host "Run 'docker compose logs -f antigravity-403-plugin' to see logs."
  }
  "2" {
    Write-Host "--- Building from Source and Running ---"
    $meta = Resolve-VersionInfo

    Write-Host "Building with the following info:"
    Write-Host "  Version: $($meta.VERSION)"
    Write-Host "  Commit: $($meta.COMMIT)"
    Write-Host "  Build Date: $($meta.BUILD_DATE)"
    Write-Host "----------------------------------------"

    $env:PLUGIN_IMAGE = "obeginners/antigravity-403-plugin:local"

    Write-Host "Building the Docker image..."
    docker compose build --build-arg VERSION=$($meta.VERSION) --build-arg COMMIT=$($meta.COMMIT) --build-arg BUILD_DATE=$($meta.BUILD_DATE)

    Write-Host "Starting the services..."
    docker compose up -d --remove-orphans --pull never

    Write-Host "Build complete. Services are starting."
    Write-Host "Run 'docker compose logs -f antigravity-403-plugin' to see logs."
  }
  default {
    Write-Host "Invalid choice. Please enter 1 or 2."
    exit 1
  }
}
