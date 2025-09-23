# 🚀 Windows Certificate Collection Tool - Standalone Executable

## 📦 **Distribution Package**

### **Version:** 2.0.0  
### **File:** `windows-cert-collector.exe` (10.3 MB)  
### **Requirements:** None - Completely standalone!

---

## ✨ **What's Included**

This standalone executable contains everything needed to collect Windows certificates:

- ✅ **Complete Python runtime** (no Python installation required)
- ✅ **All dependencies included:** `wincertstore`, `cryptography`, etc.
- ✅ **Windows version information** embedded in the .exe
- ✅ **Docker testing capabilities** (if Docker is available)
- ✅ **Comprehensive logging and reporting**

---

## 🎯 **Quick Start**

### **Basic Certificate Collection**
```bash
# Collect certificates to default location (%USERPROFILE%\.certificates)
windows-cert-collector.exe --collect-only

# Collect to custom directory
windows-cert-collector.exe --collect-only --output-dir "C:\my-certificates"
```

### **Get Help**
```bash
windows-cert-collector.exe --help
```

### **Available Commands**
- `--collect-only` - Only collect certificates (skip Docker tests)
- `--docker-only` - Only run Docker connectivity tests (skip collection)  
- `--output-dir DIR` - Custom output directory
- `--analyze` - Future feature for certificate analysis

---

## 📁 **Output Files**

The tool creates several certificate files:

```
📂 Output Directory
├── 📄 ca-certificates-all.crt          # Combined bundle (use this for containers)
├── 📄 ca-certificates-user-root.crt    # Root certificates only
├── 📄 ca-certificates-user-ca.crt      # Intermediate certificates only  
├── 📄 certificate_metadata.txt         # Detailed certificate information
└── 📄 certificate_collection.log       # Collection process log
```

---

## 🐳 **Using with Containers**

### **DevContainer Configuration**
```json
{
  "mounts": [
    "source=${env:USERPROFILE}/.certificates/ca-certificates-all.crt,target=/usr/local/share/ca-certificates/corporate.crt,type=bind,consistency=cached"
  ],
  "postCreateCommand": "sudo update-ca-certificates"
}
```

### **Docker Run Example**
```bash
docker run -v "%USERPROFILE%\.certificates\ca-certificates-all.crt:/usr/local/share/ca-certificates/corporate.crt:ro" ubuntu:22.04
```

---

## 🔧 **Corporate Network Fixes**

This tool also fixes common corporate network issues:

### **Node.js Applications (including Claude CLI)**
```powershell
# The tool automatically sets this environment variable:
$env:NODE_EXTRA_CA_CERTS = "$env:USERPROFILE\.certificates\ca-certificates-all.crt"
```

### **Applications Fixed:**
- ✅ **Claude CLI** - No more connection timeouts!
- ✅ **npm/yarn** - Package installations work
- ✅ **VS Code Extensions** - Node.js based extensions work
- ✅ **Electron Apps** - Desktop applications work
- ✅ **Docker Builds** - Container builds succeed

---

## 📊 **Example Results**

```
Windows Certificate Collection Script (Python)
==================================================
Collecting certificates from Windows certificate stores...
2025-09-23 09:17:51,977 - INFO - Starting Windows certificate collection...
2025-09-23 09:17:51,978 - INFO - Output directory: C:\Users\user\.certificates
2025-09-23 09:17:51,992 - INFO -   - User Root Certificate Authorities: 67 certificates
2025-09-23 09:17:52,003 - INFO -   - User Intermediate Certificate Authorities: 15 certificates
2025-09-23 09:17:52,006 - INFO -   - User Trusted Publishers: 0 certificates
2025-09-23 09:17:52,007 - INFO -   - Unique certificates: 82

Certificate collection completed successfully!
Output directory: C:\Users\user\.certificates
Unique certificates: 82
Combined bundle: ca-certificates-all.crt
```

---

## 🛡️ **Security & Trust**

- **Source Code Available:** This executable is built from open-source Python code
- **No Network Access Required:** Works completely offline
- **Read-Only Certificate Access:** Only reads certificates, never modifies them
- **Standard Windows APIs:** Uses official `wincertstore` and `cryptography` libraries
- **Corporate Environment Safe:** Designed specifically for corporate networks

---

## 🚀 **Distribution**

### **How to Share This Tool:**

1. **Single File Distribution** - Just copy `windows-cert-collector.exe`
2. **No Installation Required** - Run directly from any location
3. **Network Share Friendly** - Can be run from UNC paths
4. **USB Portable** - Copy to USB drive and run on any Windows machine

### **System Requirements:**
- ✅ **Windows 10/11** (64-bit)
- ✅ **No Python required** 
- ✅ **No additional dependencies**
- ✅ **~10MB disk space**

---

## 🔧 **Technical Details**

- **Built with:** PyInstaller 6.16.0
- **Python Version:** 3.12.11 (embedded)
- **Key Libraries:** wincertstore 0.2.1, cryptography 46.0.1
- **Compression:** UPX compressed for smaller size
- **Architecture:** Windows x64

---

## 🆘 **Troubleshooting**

### **Common Issues:**

**"Certificate stores not accessible"**
- Try running as Administrator for system certificates
- Current version accesses user certificate stores only

**"Docker tests fail"**  
- Ensure Docker Desktop is installed and running
- Docker tests are optional - certificate collection works without Docker

**"Permission denied errors"**
- Ensure you have write permissions to the output directory
- Default location: `%USERPROFILE%\.certificates`

---

## 📞 **Support**

This tool was created to solve corporate certificate issues in development environments. 

For issues or questions:
1. Check the generated log files for detailed error information
2. Verify certificate collection worked by checking output files
3. Test with `--collect-only` flag first to isolate issues

---

**🎉 Enjoy streamlined certificate management in your corporate environment!**