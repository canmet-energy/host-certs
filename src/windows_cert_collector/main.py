"""
Main entry point for the Windows Certificate Collection Tool
"""

import sys


def main():
    """Main entry point for the CLI tool"""
    # Handle both relative and absolute imports for PyInstaller compatibility
    try:
        from .collector import WindowsCertificateCollector
    except ImportError:
        from windows_cert_collector.collector import WindowsCertificateCollector
    
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Windows Certificate Collection Script - Simplified"
    )
    parser.add_argument("--collect-only", action="store_true", 
                       help="Only collect certificates (skip Docker tests)")
    parser.add_argument("--docker-only", action="store_true",
                       help="Only run Docker connectivity test (skip collection)")
    parser.add_argument("--output-dir", type=str,
                       help="Custom output directory (default: ~/.certificates)")
    parser.add_argument("--analyze", action="store_true",
                       help="Future: Run certificate dependency analysis")
    
    args = parser.parse_args()
    
    print("Windows Certificate Collection Script (Python)")
    print("=" * 50)
    
    try:
        # Initialize collector
        collector = WindowsCertificateCollector(args.output_dir)
        
        # Handle docker-only mode
        if args.docker_only:
            print(f"\nRunning Docker connectivity tests...")
            print("=" * 40)
            print("This will test connectivity both WITH and WITHOUT corporate certificates")
            
            if collector.run_comparison_test():
                print("SUCCESS: Docker certificate tests completed!")
                print("Check the comparison report for detailed analysis.")
            else:
                print("ERROR: Docker certificate tests failed!")
                return 1
            return 0
        
        # Collect certificates (unless docker-only)
        print("Collecting certificates from Windows certificate stores...")
        certificates = collector.collect_certificates()
        
        if not certificates:
            print("WARNING: No certificates found!")
            print("This may indicate:")
            print("  - No certificates in Windows certificate stores")  
            print("  - Insufficient permissions to read certificate stores")
            print("  - Try running as Administrator for system certificates")
            return 1
            
        # Save certificates
        collector.save_certificates(certificates)
        
        print(f"\nCertificate collection completed successfully!")
        print(f"Output directory: {collector.output_dir}")
        print(f"Unique certificates: {len(certificates)}")
        print(f"Combined bundle: ca-certificates-all.crt")
        
        # If collect-only, stop here
        if args.collect_only:
            return 0
            
        # Default behavior: run comparison tests
        print(f"\nRunning certificate comparison tests...")
        print("=" * 45)
        print("This will test connectivity both WITH and WITHOUT corporate certificates")
        
        if collector.run_comparison_test():
            print("SUCCESS: Certificate comparison tests completed!")
            print("Check the comparison report for detailed analysis.")
        else:
            print("ERROR: Certificate comparison tests failed!")
            return 1
        
        return 0
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 1
    except Exception as e:
        print(f"ERROR: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())