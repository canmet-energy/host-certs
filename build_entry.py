#!/usr/bin/env python3
"""
Standalone entry point for PyInstaller build
This avoids relative import issues when building .exe
"""

import sys
import os

# Add the src directory to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Import and run the main function
from windows_cert_collector.main import main

if __name__ == "__main__":
    sys.exit(main())