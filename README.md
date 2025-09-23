# 🏢 Windows Certificate Collection Tool

[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Windows](https://img.shields.io/badge/Platform-Windows-blue.svg)](https://www.microsoft.com/windows)
[![Enterprise](https://img.shields.io/badge/Use%20Case-Corporate%20Networks-orange.svg)](#corporate-networks)

**A modern Python tool that simplifies certificate management in corporate Windows environments, enabling seamless Docker container deployments and fixing connectivity issues for development tools.**

## 🎯 **Problem Solved**

Corporate networks often use certificate interception/inspection that breaks:
- 🐳 **Docker containers** - TLS certificate validation failures
- 🔧 **Development tools** - npm, Claude CLI, VS Code extensions
- 🌐 **HTTPS connections** - Node.js, Python requests, curl
- 📦 **Package managers** - pip, npm, yarn installations

This tool **automatically collects your Windows certificates** and provides them in formats that work with Linux containers and development tools.

---

## ✨ **Features**

### 🚀 **For End Users**
- **📦 Standalone .exe** - No Python installation required (10MB download)
- **🖱️ One-click operation** - Collect all certificates with a single command
- **📁 Multiple formats** - Combined bundle + individual store files
- **🔍 Detailed logging** - Complete audit trail and metadata

### 🛠️ **For Developers** 
- **📋 Modern Python project** - Built with `pyproject.toml` and `uv`
- **🐳 Docker integration** - Test certificate functionality in containers
- **📊 Comprehensive reporting** - Detailed analysis and comparison tools
- **🔧 CLI interface** - Full command-line automation support

### 🏢 **For IT Teams**
- **📤 Easy distribution** - Single executable file
- **🔒 Read-only access** - Never modifies existing certificates
- **📈 Usage analytics** - Detailed collection statistics
- **🚫 No admin required** - Works with user certificates

---

## 🚀 **Quick Start**

### Option 1: **Standalone Executable (Recommended)**
1. **Download** the latest `windows-cert-collector.exe` from [Releases](../../releases)
2. **Run** the executable:
   ```bash
   windows-cert-collector.exe --collect-only
   ```
3. **Use** the generated certificates: `%USERPROFILE%\.certificates\ca-certificates-all.crt`

### Option 2: **Python Package**
```bash
# Install with uv (recommended)
uv add windows-cert-collector

# Or with pip
pip install windows-cert-collector

# Run the tool
collect-certs --collect-only
```

### Option 3: **Development Setup**
```bash
# Clone and setup
git clone https://github.com/canmet-energy/windows-cert-collector.git
cd windows-cert-collector
uv venv
uv sync

# Run from source
collect-certs --collect-only
```

---

## 📋 **Usage Examples**

### **Basic Certificate Collection**
```bash
# Collect to default location
windows-cert-collector.exe --collect-only

# Collect to custom directory  
windows-cert-collector.exe --collect-only --output-dir "C:\my-certs"

# Get help
windows-cert-collector.exe --help
```

### **Docker Integration**
```bash
# DevContainer configuration (.devcontainer/devcontainer.json)
{
  "mounts": [
    "source=${env:USERPROFILE}/.certificates/ca-certificates-all.crt,target=/usr/local/share/ca-certificates/corporate.crt,type=bind,consistency=cached"
  ],
  "postCreateCommand": "sudo update-ca-certificates"
}

# Docker run example
docker run -v "%USERPROFILE%\.certificates\ca-certificates-all.crt:/usr/local/share/ca-certificates/corporate.crt:ro" ubuntu:22.04
```

### **Fix Development Tools**
```powershell
# Automatic Node.js fix (Claude CLI, npm, etc.)
$env:NODE_EXTRA_CA_CERTS = "$env:USERPROFILE\.certificates\ca-certificates-all.crt"

# Make permanent
setx NODE_EXTRA_CA_CERTS "$env:USERPROFILE\.certificates\ca-certificates-all.crt"
```

---

## 📁 **Output Files**

```
📂 ~/.certificates/
├── 📄 ca-certificates-all.crt          # 🎯 Main file - use this for containers
├── 📄 ca-certificates-user-root.crt    # Root certificates only
├── 📄 ca-certificates-user-ca.crt      # Intermediate certificates only
├── 📄 certificate_metadata.txt         # Detailed certificate information
└── 📄 certificate_collection.log       # Collection process log
```

---

## 🐳 **Docker Testing**

The tool includes built-in Docker testing to validate certificate functionality:

```bash
# Test certificates with Docker (requires Docker Desktop)
windows-cert-collector.exe

# Compare WITH vs WITHOUT corporate certificates
windows-cert-collector.exe --docker-only
```

**Example Output:**
```
Certificate Comparison Test Report
==================================
✅ WITH Corporate Certificates: 14 passed, 0 failed
❌ WITHOUT Corporate Certificates: 8 passed, 6 failed

🎯 RESULT: Corporate certificates ARE REQUIRED and WORKING!
🚀 Corporate certificates enabled 6 additional successful connections.
```

---

## 🔧 **Development Tools Fixed**

This tool resolves certificate issues for:

| Tool | Issue | Solution |
|------|-------|----------|
| **Claude CLI** | `Connection error. TypeError (fetch failed)` | ✅ `NODE_EXTRA_CA_CERTS` |
| **npm/yarn** | SSL certificate verification errors | ✅ Environment variable |
| **VS Code Extensions** | Node.js connection failures | ✅ Automatic fix |
| **Docker builds** | Certificate validation in containers | ✅ Mount certificate bundle |
| **Python requests** | SSL verification errors | ✅ Mount to container |
| **curl/wget** | TLS handshake failures | ✅ System certificate store |

---

## 🏗️ **Building from Source**

### **Build Standalone Executable**
```bash
# Quick build
.\build-exe.ps1

# Clean build with testing
.\build-exe.ps1 -Clean -Test
```

### **Development Commands**
```bash
# Install dependencies
uv sync

# Run from source
uv run collect-certs --help
```

---

## 📊 **Project Stats**

- **🎯 Purpose:** Corporate certificate management for development environments
- **📦 Package Size:** ~10MB standalone executable
- **🏢 Use Case:** Enterprise Windows environments with certificate inspection
- **🐳 Container Support:** DevContainers, Docker, Kubernetes
- **🔧 Tool Compatibility:** Node.js, Python, curl, Docker, VS Code

---

## 🤝 **Contributing**

We welcome contributions! This tool helps developers worldwide work more effectively in corporate environments.

### **Areas for Contribution:**
- 🐧 **Linux/macOS support** - Extend to other platforms
- 🔍 **Certificate analysis** - Advanced certificate dependency analysis
- 🚀 **Performance** - Optimize collection and processing
- 📖 **Documentation** - Improve guides and examples
- 🧪 **Testing** - Additional test scenarios and environments

### **Getting Started:**
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and test thoroughly
4. Submit a pull request with clear description

---

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 **Acknowledgments**

- **Natural Resources Canada (NRCan)** - Supporting open-source development tools
- **CanmetENERGY** - Energy efficiency research and development
- **Python Community** - Amazing libraries: `wincertstore`, `cryptography`, `uv`
- **Corporate IT Teams** - Inspiring the need for better certificate management tools

---

## 📞 **Support**

- 🐛 **Issues:** [GitHub Issues](../../issues)
- 📖 **Documentation:** [Wiki](../../wiki)
- 💬 **Discussions:** [GitHub Discussions](../../discussions)
- 🏢 **Enterprise Support:** Contact CanmetENERGY

---

<div align="center">

**🇨🇦 Made with ❤️ in Canada by CanmetENERGY**

*Simplifying certificate management for developers in corporate environments worldwide*

</div>

## 📁 Project Structure

```
certificates/
├── collect_certs.py           # Main Python script
├── Dockerfile                 # Unified Docker container
├── scripts/
│   └── test-connectivity.sh   # Generated test script
├── requirements.txt           # Python dependencies
└── README.md                  # This file
```

## 🚀 Quick Start

### Install Dependencies
```powershell
pip install -r requirements.txt
```

### Basic Usage

#### Default: Collect + Test
```powershell
python collect_certs.py
```
- Collects certificates from Windows stores
- Saves to `%USERPROFILE%\.certificates\`
- Runs comparison tests (with/without certificates)
- Generates comparison report in current directory

#### Collect Only
```powershell
python collect_certs.py --collect-only
```
- Only collects and saves certificates
- Skips Docker tests

#### Test Only
```powershell
python collect_certs.py --docker-only
```
- Runs comparison tests using existing certificates
- Skips certificate collection

### Command Line Options

| Option | Description |
|--------|-------------|
| `--collect-only` | Only collect certificates (skip Docker tests) |
| `--docker-only` | Only run Docker tests (skip collection) |
| `--output-dir DIR` | Custom certificate output directory |
| `--help` | Show help message |

## 📊 Output Files

### Certificates (in `%USERPROFILE%\.certificates\`)
- `ca-certificates-all.crt` - Combined certificate bundle
- `ca-certificates-user-root.crt` - Root certificates only
- `ca-certificates-user-ca.crt` - Intermediate certificates only

### Reports (in current directory)
- `certificate-comparison-report.md` - Detailed comparison analysis
- `docker-connectivity-test-results.md` - Single test results (if applicable)

## 🛠️ How It Works

1. **Certificate Collection**: Extracts certificates from Windows certificate stores using `wincertstore`
2. **Docker Testing**: Creates Ubuntu containers with/without corporate certificates
3. **Comparison**: Tests 14+ online services to measure certificate effectiveness
4. **Reporting**: Generates visual Markdown reports with emoji indicators

## 🐳 Docker Integration

The tool uses a single Dockerfile with build arguments:
- `USE_CORPORATE_CERTS=true` - Build with corporate certificates
- `USE_CORPORATE_CERTS=false` - Build without corporate certificates

## 📋 Test Coverage

Tests connectivity to:
- **AWS Services**: S3, EC2, Lambda, DynamoDB, STS, Main Portal
- **Development Tools**: GitHub, NPM Registry, PyPI, NodeSource
- **General Sites**: Google, Node.js Official

## ⚡ Performance

- **Fast**: Parallel Docker builds reduce test time
- **Efficient**: Single Dockerfile eliminates file duplication  
- **Clean**: Automatic cleanup of temporary files
- **Reliable**: Unicode-safe output handling

## 🔧 Requirements

- **Python 3.7+** with packages: `wincertstore`, `cryptography`
- **Docker Desktop** for container testing
- **Windows** (certificate collection is Windows-specific)

## 📈 Example Output

```
Certificate collection completed successfully!
Output directory: C:\Users\username\.certificates
Unique certificates: 82
Combined bundle: ca-certificates-all.crt

Running certificate comparison tests...
SUCCESS: Certificate comparison tests completed!
Check the comparison report for detailed analysis.
```

## 🎯 Use Cases

- **DevOps**: Validate corporate certificate requirements
- **Development**: Test containerized applications 
- **Security**: Audit certificate dependencies
- **Troubleshooting**: Identify connectivity issues

---

**Note**: This tool is designed for Windows environments and requires Docker for testing functionality.