"""
Windows Certificate Collection Tool

A tool for collecting Windows certificates and testing their effectiveness 
in Docker containers and enterprise environments.
"""

__version__ = "2.0.0"
__author__ = "Your Name"
__email__ = "your.email@example.com"

from .collector import WindowsCertificateCollector
from .main import main

__all__ = ["WindowsCertificateCollector", "main"]