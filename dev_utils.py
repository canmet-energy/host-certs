"""
Development and Testing Scripts

Provides utility scripts for development and testing of the 
Windows Certificate Collection Tool.
"""

import subprocess
import sys
from pathlib import Path


def install_dev_mode():
    """Install the package in development mode"""
    try:
        result = subprocess.run([
            sys.executable, "-m", "pip", "install", "-e", "."
        ], check=True, capture_output=True, text=True)
        print("✅ Package installed in development mode successfully!")
        print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Installation failed: {e}")
        print(f"Error output: {e.stderr}")
        return False


def build_package():
    """Build the package distribution"""
    try:
        result = subprocess.run([
            sys.executable, "-m", "build"
        ], check=True, capture_output=True, text=True)
        print("✅ Package built successfully!")
        print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Build failed: {e}")
        print(f"Error output: {e.stderr}")
        return False


def run_tests():
    """Run the test suite"""
    try:
        result = subprocess.run([
            sys.executable, "-m", "pytest"
        ], check=True, capture_output=True, text=True)
        print("✅ All tests passed!")
        print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Tests failed: {e}")
        print(f"Error output: {e.stderr}")
        return False


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Development utilities")
    parser.add_argument("action", choices=["install", "build", "test"],
                       help="Action to perform")
    
    args = parser.parse_args()
    
    if args.action == "install":
        install_dev_mode()
    elif args.action == "build":
        build_package()
    elif args.action == "test":
        run_tests()