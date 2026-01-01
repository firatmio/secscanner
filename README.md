# 🔒 SecScanner

<div align="center">

![SecScanner Logo](https://img.shields.io/badge/SecScanner-Security_Scanner-blue?style=for-the-badge&logo=go)

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=flat)](LICENSE)
[![CI](https://img.shields.io/badge/CI-Passing-success?style=flat&logo=github-actions)](https://github.com/security-cli/secscanner/actions)
[![SARIF](https://img.shields.io/badge/Output-SARIF_2.1-purple?style=flat)](https://sarifweb.azurewebsites.net/)

**Cloud-Native Security Scanner for Modern DevOps**

[Installation](#-installation) •
[Quick Start](#-quick-start) •
[Features](#-features) •
[Documentation](#-documentation) •
[Contributing](#-contributing)

</div>

---

## 🚀 Overview

**SecScanner** is a high-performance, modular security scanning CLI tool built with Go. Designed for 2026 and beyond, it seamlessly integrates into CI/CD pipelines while providing rich terminal output for local development.

```bash
# Scan your project in seconds
secscanner scan .
```

<details>
<summary>📸 Screenshot</summary>

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                         🔒 SECSCANNER REPORT                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

📊 SCAN SUMMARY
────────────────────────────────────────────────────────────────────────────────
  Scan Duration:          1.234s
  Targets Scanned:        156
  Total Findings:         3
  Errors:                 0

📈 SEVERITY BREAKDOWN
────────────────────────────────────────────────────────────────────────────────
  CRITICAL   [████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 1
  HIGH       [████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 2
  MEDIUM     [░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 0
```

</details>

## ✨ Features

### 🔐 Secret Detection
- **20+ Built-in Rules** for AWS, GitHub, Stripe, Slack, Google, and more
- **Entropy-based detection** for unknown secret patterns
- **Smart allowlisting** to reduce false positives
- **Masked output** - never expose secrets in logs

### ⚙️ Misconfiguration Scanner
- **Dockerfile Security** - Root user, latest tags, secrets in ENV, and more
- **Kubernetes Manifests** - Privileged containers, host access, missing limits
- **Infrastructure as Code** ready for Terraform and Helm (coming soon)

### 📊 Output Formats
- **Table (TUI)** - Beautiful terminal output with colors and progress bars
- **JSON** - Machine-readable for custom integrations
- **SARIF** - Native GitHub Code Scanning integration
- **Markdown** - Documentation-ready reports

### ⚡ Performance
- **Worker Pool Architecture** - Concurrent scanning with configurable workers
- **Memory Efficient** - Stream processing for large codebases
- **Fast Startup** - Single binary, no runtime dependencies

## 📦 Installation

### Binary (Recommended)

```bash
# macOS/Linux
curl -sSL https://github.com/security-cli/secscanner/releases/latest/download/install.sh | bash

# Windows (PowerShell)
iwr -useb https://github.com/security-cli/secscanner/releases/latest/download/install.ps1 | iex
```

### Go Install

```bash
go install github.com/security-cli/secscanner/cmd@latest
```

### From Source

```bash
git clone https://github.com/security-cli/secscanner.git
cd secscanner
go build -o secscanner ./cmd
```

### Docker

```bash
docker run --rm -v $(pwd):/scan secscanner/secscanner scan /scan
```

## 🎯 Quick Start

### Basic Scan

```bash
# Scan current directory
secscanner scan .

# Scan specific paths
secscanner scan ./src ./configs

# Scan with specific output
secscanner scan . -f json -o results.json
```

### CI/CD Integration

#### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run SecScanner
        run: |
          curl -sSL https://github.com/security-cli/secscanner/releases/latest/download/install.sh | bash
          secscanner scan . --format sarif --output results.sarif --fail-on high
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

#### GitLab CI

```yaml
security-scan:
  image: secscanner/secscanner:latest
  script:
    - secscanner scan . --format json --output gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

### Configuration File

Create `.secscanner.yaml` in your project root:

```yaml
version: "1.0"

scan:
  workers: 10
  timeout: "5m"
  exclude:
    - "**/node_modules/**"
    - "**/.git/**"
    - "**/vendor/**"
    - "**/test/**"

rules:
  disabled:
    - SEC014  # Disable generic API key detection

output:
  format: table
  color: true

ci:
  fail_on: high
  annotate_findings: true
```

## 📋 Available Commands

| Command | Description |
|---------|-------------|
| `scan [paths...]` | Scan files for security issues |
| `rules` | List all available security rules |
| `init` | Create a configuration file |
| `version` | Print version information |

### Scan Options

```bash
secscanner scan [flags]

Flags:
  -f, --format string        Output format: table, json, sarif, markdown (default "table")
  -o, --output string        Output file path
  -w, --workers int          Number of parallel workers (default 10)
  -t, --timeout duration     Scan timeout (default 5m)
  -e, --exclude strings      Exclude patterns (glob)
  -i, --include strings      Include patterns (glob)
      --severity strings     Filter by severity: critical,high,medium,low,info
      --scanners strings     Scanners to run: secrets,misconfig,all (default [all])
      --fail-on string       Exit with error on severity: critical,high,medium,low
      --rules strings        Enable specific rules by ID
      --disable-rules strings Disable specific rules by ID
  -v, --verbose              Enable verbose output
  -q, --quiet                Suppress all output except errors
      --no-color             Disable colored output
      --progress             Show progress bar (default true)
```

## 🔍 Security Rules

### Secret Detection Rules

| Rule ID | Severity | Description |
|---------|----------|-------------|
| SEC001 | CRITICAL | AWS Access Key ID |
| SEC002 | CRITICAL | AWS Secret Access Key |
| SEC003 | HIGH | GitHub Personal Access Token |
| SEC004 | HIGH | GitHub OAuth Access Token |
| SEC005 | HIGH | GitHub App Token |
| SEC006 | CRITICAL | Stripe API Key |
| SEC007 | HIGH | Google API Key |
| SEC008 | HIGH | Google OAuth Client Secret |
| SEC009 | HIGH | Slack Bot Token |
| SEC010 | MEDIUM | Slack Webhook URL |
| SEC011 | CRITICAL | RSA Private Key |
| SEC012 | CRITICAL | SSH Private Key |
| SEC013 | MEDIUM | JSON Web Token |
| SEC014 | MEDIUM | Generic API Key |
| SEC015 | HIGH | Password in Code |
| SEC016 | HIGH | Database Connection String |
| SEC017 | HIGH | Twilio API Key |
| SEC018 | HIGH | SendGrid API Key |
| SEC019 | HIGH | npm Token |
| SEC020 | HIGH | Discord Bot Token |

### Dockerfile Rules

| Rule ID | Severity | Description |
|---------|----------|-------------|
| DOCKER001 | HIGH | Running as Root User |
| DOCKER002 | MEDIUM | Using Latest Tag |
| DOCKER003 | MEDIUM | No Tag Specified |
| DOCKER004 | LOW | ADD Instead of COPY |
| DOCKER005 | HIGH | Secrets in Environment Variables |
| DOCKER006 | CRITICAL | Curl/Wget Piped to Shell |
| DOCKER007 | LOW | apt-get without --no-install-recommends |
| DOCKER008 | LOW | Missing apt-get Clean |
| DOCKER009 | MEDIUM | HEALTHCHECK Not Defined |
| DOCKER010 | MEDIUM | Privileged Port Exposed |
| DOCKER011 | MEDIUM | sudo Usage Detected |
| DOCKER012 | HIGH | Missing USER Instruction |

### Kubernetes Rules

| Rule ID | Severity | Description |
|---------|----------|-------------|
| K8S001 | CRITICAL | Privileged Container |
| K8S002 | HIGH | Running as Root |
| K8S003 | MEDIUM | Root Filesystem Not Read-Only |
| K8S004 | HIGH | Privilege Escalation Allowed |
| K8S005 | HIGH | Host Network Access |
| K8S006 | HIGH | Host PID Namespace |
| K8S007 | MEDIUM | Host IPC Namespace |
| K8S008 | CRITICAL | Dangerous Capabilities Added |
| K8S009 | MEDIUM | No Resource Limits |
| K8S010 | MEDIUM | Latest Image Tag |
| K8S011 | HIGH | Host Path Volume Mount |
| K8S012 | LOW | Default Service Account |
| K8S013 | MEDIUM | Secrets in Environment Variables |
| K8S014 | MEDIUM | Missing Network Policy |
| K8S015 | CRITICAL | Writable /proc Mount |

## 🏗️ Architecture

```
secscanner/
├── cmd/
│   ├── main.go              # Entry point
│   └── cli/
│       ├── root.go          # Root command & flags
│       ├── scan.go          # Scan command
│       └── config.go        # Configuration handling
├── pkg/
│   ├── scanner/
│   │   ├── types.go         # Core types & interfaces
│   │   ├── pool.go          # Worker pool implementation
│   │   ├── secrets.go       # Secret detection scanner
│   │   ├── misconfig.go     # Misconfiguration scanner
│   │   └── scanner_test.go  # Unit tests
│   ├── report/
│   │   ├── reporter.go      # Report formatters
│   │   └── sarif.go         # SARIF format support
│   └── utils/
│       ├── filewalker.go    # File system traversal
│       └── progress.go      # Progress indicators
├── go.mod
├── go.sum
└── README.md
```

## 🛠️ Development

### Prerequisites

- Go 1.23 or later
- Git

### Building

```bash
# Development build
go build -o secscanner ./cmd

# Production build with version info
go build -ldflags "-X main.version=1.0.0 -X main.commit=$(git rev-parse HEAD)" -o secscanner ./cmd
```

### Testing

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific package tests
go test ./pkg/scanner/...
```

### Linting

```bash
# Install golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run linter
golangci-lint run
```

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

### Adding Custom Rules

1. **YAML Rules** (Coming Soon)
```yaml
# .secscanner.yaml
rules:
  custom:
    - id: CUSTOM001
      name: "Internal API Key"
      pattern: "INTERNAL_[A-Z0-9]{32}"
      severity: HIGH
      remediation: "Use environment variables instead"
```

2. **Go Interface**
```go
type Scanner interface {
    Name() string
    Description() string
    Scan(ctx context.Context, target Target) ([]Finding, error)
    SupportedTypes() []TargetType
}
```

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- [spf13/cobra](https://github.com/spf13/cobra) - CLI framework
- [fatih/color](https://github.com/fatih/color) - Terminal colors
- [owenrumney/go-sarif](https://github.com/owenrumney/go-sarif) - SARIF support
- Inspired by [truffleHog](https://github.com/trufflesecurity/trufflehog), [gitleaks](https://github.com/gitleaks/gitleaks), and [trivy](https://github.com/aquasecurity/trivy)

---

<div align="center">

**Built with ❤️ by [firatmio](https://github.com/firatmio)**

[Report Bug](https://github.com/firatmio/secscanner/issues) •
[Request Feature](https://github.com/firatmio/secscanner/issues)

</div>
