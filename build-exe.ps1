#!/usr/bin/env powershell
<#
.SYNOPSIS
    Build script for Windows Certificate Collection Tool
    
.DESCRIPTION
    This script builds a standalone Windows .exe from the Python project using PyInstaller.
    The resulting executable includes all dependencies and requires no Python installation.
    
.PARAMETER Clean
    Clean build directories before building
    
.PARAMETER Test
    Run tests after building
    
.EXAMPLE
    .\build-exe.ps1
    Build the executable
    
.EXAMPLE  
    .\build-exe.ps1 -Clean -Test
    Clean, build, and test the executable
#>

param(
    [switch]$Clean,
    [switch]$Test
)

# Colors for output
$ErrorColor = "Red"
$SuccessColor = "Green" 
$InfoColor = "Cyan"
$WarningColor = "Yellow"

function Write-Info($message) {
    Write-Host "INFO: $message" -ForegroundColor $InfoColor
}

function Write-Success($message) {
    Write-Host "SUCCESS: $message" -ForegroundColor $SuccessColor
}

function Write-Error($message) {
    Write-Host "ERROR: $message" -ForegroundColor $ErrorColor
}

function Write-Warning($message) {
    Write-Host "WARNING: $message" -ForegroundColor $WarningColor
}

# Main build function
function Build-Executable {
    Write-Info "Building Windows Certificate Collection Tool executable..."
    
    # Check if we're in the right directory
    if (!(Test-Path "pyproject.toml")) {
        Write-Error "pyproject.toml not found. Please run this script from the project root."
        exit 1
    }
    
    # Check if virtual environment exists
    if (!(Test-Path ".venv\Scripts\activate.ps1")) {
        Write-Error "Virtual environment not found. Please run 'uv venv' first."
        exit 1
    }
    
    # Clean build directories if requested
    if ($Clean) {
        Write-Info "Cleaning build directories..."
        if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
        if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }  
        if (Test-Path "*.spec") { Remove-Item -Force "*.spec" }
        Write-Success "Build directories cleaned"
    }
    
    # Activate virtual environment and build
    Write-Info "Activating virtual environment and building executable..."
    
    $buildArgs = @(
        "--onefile",
        "--name", "host-certs",
        "--paths=src", 
        "--version-file=version_info.txt",
        "--noconfirm",
        "src/host_certs/main.py"
    )
    
    try {
        & ".venv\Scripts\python" -m PyInstaller @buildArgs
        
        if (Test-Path "dist\host-certs.exe") {
            $fileInfo = Get-Item "dist\host-certs.exe"
            $sizeMB = [math]::Round($fileInfo.Length / 1MB, 2)
            Write-Success "Build completed successfully!"
            Write-Info "Executable: dist\host-certs.exe"
            Write-Info "Size: $sizeMB MB"
        } else {
            Write-Error "Build failed - executable not found"
            exit 1
        }
    } catch {
        Write-Error "Build failed: $($_.Exception.Message)"
        exit 1
    }
}

# Test function
function Test-Executable {
    Write-Info "Testing the built executable..."
    
    if (!(Test-Path "dist\host-certs.exe")) {
        Write-Error "Executable not found. Build first."
        exit 1
    }
    
    try {
        # Test help command
        Write-Info "Testing --help command..."
        $helpOutput = & ".\dist\host-certs.exe" --help 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Help command works"
        } else {
            Write-Error "Help command failed"
            Write-Host $helpOutput
            exit 1
        }
        
        # Test certificate collection to temp directory
        Write-Info "Testing certificate collection..."
        $testDir = "test-exe-output-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        $collectOutput = & ".\dist\host-certs.exe" --collect-only --output-dir $testDir 2>&1
        
        if ($LASTEXITCODE -eq 0 -and (Test-Path "$testDir\host.crt")) {
            Write-Success "Certificate collection test passed"
            $certCount = (Get-Content "$testDir\host.crt" | Select-String "BEGIN CERTIFICATE").Count
            Write-Info "Collected $certCount certificates"
            
            # Clean up test directory
            Remove-Item -Recurse -Force $testDir
        } else {
            Write-Error "Certificate collection test failed"
            Write-Host $collectOutput
            exit 1
        }
        
        Write-Success "All tests passed!"
        
    } catch {
        Write-Error "Testing failed: $($_.Exception.Message)"
        exit 1
    }
}

# Main execution
try {
    Write-Info "Windows Certificate Collection Tool - Build Script"
    Write-Info "================================================"
    
    Build-Executable
    
    if ($Test) {
        Test-Executable
    }
    
    Write-Success "Build process completed successfully!"
    Write-Info ""
    Write-Info "Ready for distribution:"
    Write-Info "   Executable: .\dist\host-certs.exe"
    Write-Info "   Documentation: .\EXE_DISTRIBUTION_README.md" 
    Write-Info ""
    Write-Info "Quick test: .\dist\host-certs.exe --help"
    
} catch {
    Write-Error "Build script failed: $($_.Exception.Message)"
    exit 1
}
