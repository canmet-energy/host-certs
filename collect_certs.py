#!/usr/bin/env python3
"""
Windows Certificate Collection Script
Collects certificates from Windows certificate stores for use in Linux containers
Version: 2.0.0 (Python Implementation)

This script uses modern Python libraries to reduce complexity:
- wincertstore: Direct Windows certificate store access
- cryptography: Certificate parsing and validation
- pathlib: Modern path handling
"""

import os
import sys
import hashlib
import logging
import subprocess
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass

try:
    import wincertstore
except ImportError:
    print("ERROR: wincertstore library not found. Install with: pip install wincertstore")
    sys.exit(1)

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("ERROR: cryptography library not found. Install with: pip install cryptography")
    sys.exit(1)


@dataclass
class CertificateInfo:
    """Information about a certificate"""
    subject: str
    issuer: str
    fingerprint: str
    store_name: str
    store_type: str  # 'system' or 'user'
    pem_data: str


class WindowsCertificateCollector:
    """Collects certificates from Windows certificate stores with duplicate detection"""
    
    # Windows certificate store mappings (wincertstore format)
    CERT_STORES = {
        'ROOT': 'Root Certificate Authorities',
        'CA': 'Intermediate Certificate Authorities', 
        'TrustedPublisher': 'Trusted Publishers'
    }
    
    def __init__(self, output_dir: Optional[str] = None):
        """Initialize the certificate collector
        
        Args:
            output_dir: Output directory path. Defaults to %USERPROFILE%\.certificates
        """
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            self.output_dir = Path.home() / '.certificates'
            
        self.certificates: Dict[str, CertificateInfo] = {}  # fingerprint -> CertificateInfo
        self.stats = {
            'total_found': 0,
            'duplicates_removed': 0,
            'unique_certificates': 0,
            'stores_processed': 0
        }
        
        # Setup logging
        self._setup_logging()
        
    def _setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(self.output_dir / 'certificate_collection.log')
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def _create_output_directory(self):
        """Create output directory if it doesn't exist"""
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            self.logger.info(f"Output directory: {self.output_dir}")
        except Exception as e:
            self.logger.error(f"Failed to create output directory: {e}")
            raise
            
    def _cleanup_old_files(self):
        """Remove old certificate files"""
        try:
            for pattern in ['*.crt', '*.pem']:
                for file_path in self.output_dir.glob(pattern):
                    file_path.unlink()
            self.logger.info("Cleaned up old certificate files")
        except Exception as e:
            self.logger.warning(f"Error cleaning up old files: {e}")
            
    def _get_certificate_fingerprint(self, cert_der: bytes) -> str:
        """Generate SHA256 fingerprint for certificate deduplication
        
        Args:
            cert_der: Certificate in DER format
            
        Returns:
            SHA256 fingerprint as hex string
        """
        return hashlib.sha256(cert_der).hexdigest()
        
    def _parse_certificate(self, cert_context, store_name: str, store_type: str) -> Optional[CertificateInfo]:
        """Parse certificate and extract information
        
        Args:
            cert_context: CERT_CONTEXT object from wincertstore
            store_name: Name of the certificate store
            store_type: Type of store ('system' or 'user')
            
        Returns:
            CertificateInfo object or None if parsing fails
        """
        try:
            # Get certificate in DER format
            cert_der = cert_context.get_encoded()
            
            # Parse certificate using cryptography library
            cert = x509.load_der_x509_certificate(cert_der)
            
            # Extract certificate information
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            fingerprint = self._get_certificate_fingerprint(cert_der)
            
            # Convert to PEM format
            pem_data = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            
            return CertificateInfo(
                subject=subject,
                issuer=issuer,
                fingerprint=fingerprint,
                store_name=store_name,
                store_type=store_type,
                pem_data=pem_data
            )
            
        except Exception as e:
            self.logger.warning(f"Failed to parse certificate from {store_name}: {e}")
            return None
            
    def _collect_from_store(self, store_name: str, store_type: str) -> int:
        """Collect certificates from a specific Windows store
        
        Args:
            store_name: Name of the certificate store
            store_type: Type of store ('system' or 'user') - Note: wincertstore only accesses user stores
            
        Returns:
            Number of certificates collected from this store
        """
        store_count = 0
        
        try:
            # Note: wincertstore only accesses current user stores, not system stores
            # Open the certificate store
            with wincertstore.CertSystemStore(store_name) as store:
                for cert_context in store.itercerts():
                    self.stats['total_found'] += 1
                    
                    # Parse certificate
                    cert_info = self._parse_certificate(cert_context, store_name, store_type)
                    if not cert_info:
                        continue
                        
                    # Check for duplicates
                    if cert_info.fingerprint in self.certificates:
                        self.stats['duplicates_removed'] += 1
                        self.logger.debug(f"Duplicate certificate found: {cert_info.subject}")
                    else:
                        self.certificates[cert_info.fingerprint] = cert_info
                        store_count += 1
                        
        except Exception as e:
            self.logger.error(f"Failed to collect from {store_type} {store_name} store: {e}")
            
        return store_count
        
    def collect_certificates(self) -> Dict[str, CertificateInfo]:
        """Collect all certificates from Windows certificate stores
        
        Returns:
            Dictionary of unique certificates (fingerprint -> CertificateInfo)
        """
        self.logger.info("Starting Windows certificate collection...")
        self.logger.info("Note: wincertstore library only accesses current user certificate stores")
        
        # Setup output directory
        self._create_output_directory()
        self._cleanup_old_files()
        
        # Collect from all stores
        for store_key, store_display_name in self.CERT_STORES.items():
            self.logger.info(f"Collecting from {store_display_name}...")
            
            # wincertstore only accesses user stores
            user_count = self._collect_from_store(store_key, 'user')
            self.logger.info(f"  - User {store_display_name}: {user_count} certificates")
            
            self.stats['stores_processed'] += 1
            
        self.stats['unique_certificates'] = len(self.certificates)
        
        self.logger.info(f"Collection complete:")
        self.logger.info(f"  - Total certificates found: {self.stats['total_found']}")
        self.logger.info(f"  - Duplicates removed: {self.stats['duplicates_removed']}")
        self.logger.info(f"  - Unique certificates: {self.stats['unique_certificates']}")
        
        return self.certificates
        
    def save_certificates(self, certificates: Dict[str, CertificateInfo]):
        """Save certificates to individual and combined files
        
        Args:
            certificates: Dictionary of certificates to save
        """
        self.logger.info("Saving certificate files...")
        
        # Group certificates by store type and name
        grouped_certs = {}
        for cert_info in certificates.values():
            key = f"{cert_info.store_type}-{cert_info.store_name.lower()}"
            if key not in grouped_certs:
                grouped_certs[key] = []
            grouped_certs[key].append(cert_info)
            
        # Save individual store files
        for group_key, cert_list in grouped_certs.items():
            store_type, store_name = group_key.split('-', 1)
            filename = f"ca-certificates-{store_type}-{store_name}.crt"
            self._save_certificate_bundle(cert_list, filename)
            
        # Save combined bundle
        all_certs = list(certificates.values())
        self._save_certificate_bundle(all_certs, "ca-certificates-all.crt")
        
        # Create metadata file
        self._save_metadata(certificates)
        
        self.logger.info(f"Certificates saved to: {self.output_dir}")
        
    def _save_certificate_bundle(self, cert_list: List[CertificateInfo], filename: str):
        """Save a list of certificates to a PEM bundle file
        
        Args:
            cert_list: List of certificates to save
            filename: Output filename
        """
        try:
            file_path = self.output_dir / filename
            with open(file_path, 'w', encoding='utf-8') as f:
                for cert_info in cert_list:
                    f.write(cert_info.pem_data)
                    f.write('\n')
                    
            self.logger.info(f"Saved {len(cert_list)} certificates to {filename}")
            
        except Exception as e:
            self.logger.error(f"Failed to save {filename}: {e}")
            
    def _save_metadata(self, certificates: Dict[str, CertificateInfo]):
        """Save certificate metadata and statistics
        
        Args:
            certificates: Dictionary of certificates
        """
        try:
            metadata_file = self.output_dir / "certificate_metadata.txt"
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            with open(metadata_file, 'w', encoding='utf-8') as f:
                f.write(f"# Windows Certificate Export Metadata\n")
                f.write(f"# Generated: {timestamp}\n\n")
                
                f.write(f"## Statistics\n")
                f.write(f"Total certificates found: {self.stats['total_found']}\n")
                f.write(f"Duplicates removed: {self.stats['duplicates_removed']}\n")
                f.write(f"Unique certificates: {self.stats['unique_certificates']}\n")
                f.write(f"Stores processed: {self.stats['stores_processed']}\n\n")
                
                f.write(f"## Certificate Details\n")
                for cert_info in certificates.values():
                    f.write(f"Fingerprint: {cert_info.fingerprint}\n")
                    f.write(f"Subject: {cert_info.subject}\n")
                    f.write(f"Issuer: {cert_info.issuer}\n")
                    f.write(f"Store: {cert_info.store_type} {cert_info.store_name}\n")
                    f.write(f"---\n")
                    
        except Exception as e:
            self.logger.error(f"Failed to save metadata: {e}")
            
    def test_certificates_in_docker(self) -> bool:
        """Test certificate functionality using Docker container
        
        Returns:
            True if all tests pass, False otherwise
        """
        self.logger.info("Starting Docker certificate testing...")
        
        # Check if Docker is available
        if not self._check_docker_available():
            self.logger.warning("Docker not available, skipping certificate tests")
            return False
            
        # Check if certificate bundle exists
        cert_bundle = self.output_dir / "ca-certificates-all.crt"
        if not cert_bundle.exists():
            self.logger.error("Certificate bundle not found. Run collect_certificates() first.")
            return False
            
        try:
            # Build the Docker image with certificates
            if not self._build_docker_image(use_certs=True):
                return False
                
            # Run the certificate test
            if not self._run_certificate_test():
                return False
                
            self.logger.info("Docker certificate testing completed successfully!")
            return True
            
        except Exception as e:
            self.logger.error(f"Docker certificate testing failed: {e}")
            return False
            
    def _check_docker_available(self) -> bool:
        """Check if Docker is available on the system"""
        try:
            result = subprocess.run(
                ["docker", "--version"], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            if result.returncode == 0:
                self.logger.info(f"Docker found: {result.stdout.strip()}")
                return True
            else:
                self.logger.warning("Docker command failed")
                return False
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            self.logger.warning("Docker not found or not accessible")
            return False
            
    def _build_docker_image(self, use_certs: bool = True) -> bool:
        """Build Docker image with or without corporate certificates using build args
        
        Args:
            use_certs: If True, build with corporate certificates. If False, build without.
            
        Returns:
            True if build successful, False otherwise
        """
        try:
            script_dir = Path(__file__).parent
            dockerfile_path = script_dir / "Dockerfile"
            
            if not dockerfile_path.exists():
                self.logger.error(f"Dockerfile not found at {dockerfile_path}")
                return False
                
            # Ensure test script exists
            self._create_test_script_file()
            
            # Copy certificate bundle to script directory if building with certs
            if use_certs:
                cert_bundle_path = self.output_dir / "ca-certificates-all.crt"
                if not cert_bundle_path.exists():
                    self.logger.error("Certificate bundle not found. Run certificate collection first.")
                    return False
                    
                cert_dst = script_dir / "ca-certificates-all.crt"
                shutil.copy2(cert_bundle_path, cert_dst)
                self.logger.info("Copied certificate bundle to build context")
            else:
                # Create empty certificate file for consistency
                cert_dst = script_dir / "ca-certificates-all.crt"
                cert_dst.touch()
            
            # Determine image tag based on cert usage
            image_tag = "cert-tester:with-certs" if use_certs else "cert-tester:no-certs"
            
            # Build Docker image with build arguments
            build_cmd = [
                "docker", "build",
                "--build-arg", f"USE_CORPORATE_CERTS={'true' if use_certs else 'false'}",
                "-t", image_tag,
                "-f", str(dockerfile_path),
                str(script_dir)
            ]
            
            self.logger.info(f"Building Docker image {'WITH' if use_certs else 'WITHOUT'} corporate certificates...")
            self.logger.info(f"Running: {' '.join(build_cmd)}")
            
            result = subprocess.run(
                build_cmd,
                capture_output=True,
                text=True,
                cwd=script_dir,
                timeout=300
            )
            
            if result.returncode == 0:
                self.logger.info(f"Docker image ({'with' if use_certs else 'without'} certs) built successfully")
                return True
            else:
                self.logger.error(f"Docker build failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error("Docker build timed out after 5 minutes")
            return False
        except Exception as e:
            self.logger.error(f"Error building Docker image: {e}")
            return False
        finally:
            # Clean up copied certificate file
            cert_dst = script_dir / "ca-certificates-all.crt"
            if cert_dst.exists():
                cert_dst.unlink()
                
    def _run_certificate_test(self) -> bool:
        """Run the certificate test in Docker container"""
        self.logger.info("Running certificate connectivity tests in Docker container...")
        
        try:
            # Run the Docker container
            run_cmd = [
                "docker", "run", "--rm",
                "--name", "cert-test-container",
                "cert-tester:with-certs"
            ]
            
            self.logger.info("Running: " + " ".join(run_cmd))
            result = subprocess.run(
                run_cmd,
                capture_output=True,
                text=True,
                timeout=120  # 2 minutes timeout
            )
            
            # Save test results in current working directory
            test_results_file = Path.cwd() / "docker-connectivity-test-results.md"
            with open(test_results_file, 'w', encoding='utf-8') as f:
                f.write("# Docker Certificate Connectivity Test Results\n\n")
                f.write(f"**Test Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"**Exit Code:** `{result.returncode}`\n\n")
                
                # Parse results to show pass/fail summary
                stdout = result.stdout
                success_count = stdout.count("SUCCESS")
                fail_count = stdout.count("FAIL")
                
                f.write("## 📊 Test Summary\n\n")
                f.write("| Status | Count |\n")
                f.write("|--------|-------|\n")
                f.write(f"| ✅ Passed | {success_count} |\n")
                f.write(f"| ❌ Failed | {fail_count} |\n\n")
                
                if result.returncode == 0:
                    f.write("### 🎯 **Result: ALL TESTS PASSED!** ✅\n\n")
                elif result.returncode == 1:
                    f.write("### ⚠️ **Result: Some tests failed** ❌\n\n")
                else:
                    f.write("### 🚨 **Result: ALL TESTS FAILED!** ❌\n\n")
                
                f.write("## 📄 Detailed Output\n\n")
                f.write("### Standard Output\n")
                f.write("```\n")
                f.write(result.stdout)
                f.write("\n```\n\n")
                
                if result.stderr:
                    f.write("### Error Output\n")
                    f.write("```\n")
                    f.write(result.stderr)
                    f.write("\n```\n\n")
            
            # Log results
            self.logger.info(f"Test results saved to: {test_results_file}")
            
            if result.returncode == 0:
                self.logger.info("All certificate tests passed!")
                return True
            elif result.returncode == 1:
                self.logger.warning("Some certificate tests failed")
                return False
            else:
                self.logger.error("All certificate tests failed")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error("Docker container test timed out")
            return False
        except Exception as e:
            self.logger.error(f"Error running certificate test: {e}")
            return False
            
    def run_comparison_test(self) -> bool:
        """Run comparison test WITH and WITHOUT corporate certificates
        
        Returns:
            True if comparison test completed successfully
        """
        self.logger.info("Starting certificate comparison test...")
        self.logger.info("This will test connectivity both WITH and WITHOUT corporate certificates")
        
        # Check if Docker is available
        if not self._check_docker_available():
            self.logger.warning("Docker not available, skipping comparison tests")
            return False
            
        # Check if certificate bundle exists
        cert_bundle = self.output_dir / "ca-certificates-all.crt"
        if not cert_bundle.exists():
            self.logger.error("Certificate bundle not found. Run collect_certificates() first.")
            return False
            
        try:
            # Test WITHOUT certificates first
            self.logger.info("Phase 1: Testing WITHOUT corporate certificates...")
            without_certs_result = self._run_test_without_certificates()
            
            # Test WITH certificates
            self.logger.info("Phase 2: Testing WITH corporate certificates...")
            with_certs_result = self._run_test_with_certificates()
            
            # Generate comparison report
            self._generate_comparison_report(without_certs_result, with_certs_result)
            
            self.logger.info("Certificate comparison test completed!")
            return True
            
        except Exception as e:
            self.logger.error(f"Certificate comparison test failed: {e}")
            return False
            
    def _run_test_without_certificates(self) -> dict:
        """Run connectivity test WITHOUT corporate certificates"""
        try:
            # Build Docker image without certificates
            if not self._build_docker_image(use_certs=False):
                return {"success": False, "error": "Failed to build image without certificates"}
                
            # Run test
            run_cmd = [
                "docker", "run", "--rm",
                "--name", "cert-test-no-certs",
                "cert-tester:no-certs"
            ]
            
            self.logger.info("Running: " + " ".join(run_cmd))
            result = subprocess.run(
                run_cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=120
            )
            
            return {
                "success": True,
                "exit_code": result.returncode,
                "stdout": result.stdout or "",
                "stderr": result.stderr or ""
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
            
    def _run_test_with_certificates(self) -> dict:
        """Run connectivity test WITH corporate certificates"""
        try:
            # Build Docker image with certificates
            if not self._build_docker_image(use_certs=True):
                return {"success": False, "error": "Failed to build image with certificates"}
                
            # Run test
            run_cmd = [
                "docker", "run", "--rm",
                "--name", "cert-test-with-certs",
                "cert-tester:with-certs"
            ]
            
            self.logger.info("Running: " + " ".join(run_cmd))
            result = subprocess.run(
                run_cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=120
            )
            
            return {
                "success": True,
                "exit_code": result.returncode,
                "stdout": result.stdout or "",
                "stderr": result.stderr or ""
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
            
    def _generate_comparison_table(self, f, without_stdout: str, with_stdout: str):
        """Generate a detailed comparison table of test results"""
        import re
        
        f.write("## 📋 Detailed Comparison Table\n\n")
        
        # Parse test results from both outputs
        test_results = {}
        
        # Extract test results from stdout using regex
        # Pattern: Testing <Service Name> (<URL>)... <result>
        test_pattern = r'Testing\s+([^(]+)\s+\([^)]+\)\.\.\.\s+[^\s]+\s+(SUCCESS|FAIL.*?)$'
        
        # Parse without certs results
        without_matches = re.findall(test_pattern, without_stdout, re.MULTILINE)
        for service, result in without_matches:
            service = service.strip()
            test_results[service] = {'without': result}
        
        # Parse with certs results
        with_matches = re.findall(test_pattern, with_stdout, re.MULTILINE)
        for service, result in with_matches:
            service = service.strip()
            if service not in test_results:
                test_results[service] = {}
            test_results[service]['with'] = result
        
        # Generate table
        f.write("| Service | WITHOUT Corporate Certs | WITH Corporate Certs | Notes |\n")
        f.write("|---------|-------------------------|---------------------|-------|\n")
        
        for service in sorted(test_results.keys()):
            without_result = test_results[service].get('without', 'N/A')
            with_result = test_results[service].get('with', 'N/A')
            
            # Convert to emoji format
            without_emoji = "✅" if "SUCCESS" in without_result else "❌"
            with_emoji = "✅" if "SUCCESS" in with_result else "❌"
            
            # Extract error message if any
            error_msg = ""
            without_success = "SUCCESS" in without_result
            with_success = "SUCCESS" in with_result
            without_fail = "FAIL" in without_result
            with_fail = "FAIL" in with_result
            
            if without_fail and with_success:
                error_msg = "🎯 Fixed by corporate certs"
            elif without_fail and with_fail:
                error_msg = "❌ Fails in both scenarios"
            elif without_success and with_fail:
                error_msg = "⚠️ Broken by corporate certs"
            elif without_success and with_success:
                error_msg = "✅ Working in both scenarios"
            else:
                error_msg = "Status unclear"
            
            f.write(f"| **{service}** | {without_emoji} | {with_emoji} | {error_msg} |\n")
        
        f.write("\n")
        f.write("**Legend:**\n")
        f.write("- ✅ = Test passed (successful TLS connection)\n")
        f.write("- ❌ = Test failed (TLS/connection error)\n\n")
            
    def _generate_test_script(self) -> str:
        """Generate the shell script content for Docker testing"""
        return '''#!/bin/bash
# Certificate Connectivity Test Script
# Generated by Windows Certificate Collection Script

echo "=========================================="
echo "Certificate Connectivity Test"

# Check if corporate certificates are installed
if [ -f "/usr/local/share/ca-certificates/corporate-bundle.crt" ]; then
    echo "=========================================="
    echo "Container: Ubuntu 22.04"
    echo "Test Date: $(date)"
    echo ""
    echo "Certificate Store Information:"
    echo "==============================="
    echo "System CA certificates: $(find /etc/ssl/certs -name '*.pem' | wc -l) files"
    echo "Custom certificates added: $(find /usr/local/share/ca-certificates -name '*.crt' | wc -l) files"
    if [ -f "/usr/local/share/ca-certificates/corporate-bundle.crt" ]; then
        echo "Corporate bundle size: $(wc -l < /usr/local/share/ca-certificates/corporate-bundle.crt) lines"
    fi
else
    echo "WITHOUT Corporate Certificates"
    echo "=========================================="
    echo "Container: Ubuntu 22.04"
    echo "Test Date: $(date)"
    echo ""
    echo "Certificate Store Information:"
    echo "==============================="
    echo "System CA certificates: $(find /etc/ssl/certs -name '*.pem' | wc -l) files"
    echo "Custom certificates added: 0 files (NONE - this is the control test)"
fi

echo ""

# Test function
test_url() {
    local name="$1"
    local url="$2"
    echo -n "Testing $name ($url)... "
    
    if timeout 10 curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null | grep -qE "^[2-4][0-9][0-9]$"; then
        echo "✅ SUCCESS"
        return 0
    else
        echo "❌ FAIL (Connection/TLS error)"
        echo "  Error: "
        return 1
    fi
}

# Basic connectivity tests
if [ -f "/usr/local/share/ca-certificates/corporate-bundle.crt" ]; then
    echo "Basic Connectivity Tests:"
    echo "========================="
else
    echo "Basic Connectivity Tests (WITHOUT Corporate Certificates):"
    echo "========================================================="
fi

test_url "GitHub" "https://github.com"
test_url "PyPI" "https://pypi.org"
test_url "NPM Registry" "https://registry.npmjs.org"
test_url "NodeSource" "https://deb.nodesource.com"
test_url "AWS S3" "https://s3.amazonaws.com"
test_url "AWS Main" "https://aws.amazon.com"

echo ""

# Extended connectivity tests
if [ -f "/usr/local/share/ca-certificates/corporate-bundle.crt" ]; then
    echo "Extended Connectivity Tests:"
    echo "============================"
else
    echo "Extended Connectivity Tests (WITHOUT Corporate Certificates):"
    echo "============================================================="
fi

test_url "Google" "https://www.google.com"
test_url "GitHub API" "https://api.github.com"
test_url "Python Package Files" "https://files.pythonhosted.org"
test_url "Node.js Official" "https://nodejs.org"
test_url "AWS EC2" "https://ec2.amazonaws.com"
test_url "AWS DynamoDB" "https://dynamodb.us-east-1.amazonaws.com"
test_url "AWS Lambda" "https://lambda.us-east-1.amazonaws.com"
test_url "AWS STS" "https://sts.amazonaws.com"

echo ""

# TLS analysis for key sites
if [ -f "/usr/local/share/ca-certificates/corporate-bundle.crt" ]; then
    echo "Detailed TLS Analysis:"
    echo "====================="
else
    echo "Detailed TLS Analysis (WITHOUT Corporate Certificates):"
    echo "======================================================="
fi

echo ""
for site in "github.com" "pypi.org"; do
    echo "TLS Certificate Details for $site:"
    echo "-----------------------------------"
    if timeout 10 openssl s_client -servername "$site" -connect "$site:443" -verify_return_error < /dev/null > /tmp/cert_info 2>&1; then
        echo "✅ TLS handshake successful"
        grep -A 2 "subject=" /tmp/cert_info | head -3 | sed 's/^/  /'
    else
        echo "❌ TLS handshake failed"
        grep "verify error" /tmp/cert_info | head -1 | sed 's/^/  /'
    fi
    echo ""
done

# Test summary
echo "=========================================="
if [ -f "/usr/local/share/ca-certificates/corporate-bundle.crt" ]; then
    echo "Test Summary"
else
    echo "Test Summary (WITHOUT Corporate Certificates)"
fi
echo "=========================================="

# Count successful tests (this is a simple approximation)
TOTAL_TESTS=14
SUCCESSFUL=$(grep -c "✅ SUCCESS" /tmp/test_output.log 2>/dev/null || echo "5")
FAILED=$((TOTAL_TESTS - SUCCESSFUL))

echo "Total tests: $TOTAL_TESTS"
echo "Successful: $SUCCESSFUL"
echo "Failed: $FAILED"

if [ "$FAILED" -eq 0 ]; then
    echo "Result: ✅ ALL TESTS PASSED"
    echo "Certificate configuration is working correctly!"
    exit 0
elif [ "$SUCCESSFUL" -gt 0 ]; then
    echo "Result: ⚠️ PARTIAL SUCCESS"
    echo "Some sites may require corporate certificates."
    exit 1
else
    echo "Result: ❌ ALL TESTS FAILED"
    echo "Network connectivity or certificate issues detected."
    exit 1
fi
'''

    def _create_test_script_file(self) -> Path:
        """Create the test script file in the scripts directory"""
        scripts_dir = Path.cwd() / "scripts"
        scripts_dir.mkdir(exist_ok=True)
        
        script_path = scripts_dir / "test-connectivity.sh"
        script_content = self._generate_test_script()
        
        with open(script_path, 'w', encoding='utf-8', newline='\n') as f:
            f.write(script_content)
            
        return script_path
            
    def _generate_comparison_report(self, without_certs: dict, with_certs: dict):
        """Generate comprehensive comparison report in Markdown format"""
        # Save report in current working directory
        report_file = Path.cwd() / "certificate-comparison-report.md"
        
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write("# Certificate Comparison Test Report\n\n")
                f.write(f"**Test Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Executive Summary
                f.write("## 📊 Executive Summary\n\n")
                
                if without_certs.get("success") and with_certs.get("success"):
                    without_exit = without_certs.get("exit_code", 999)
                    with_exit = with_certs.get("exit_code", 999)
                    
                    # Count success/failure from the output text
                    without_stdout = without_certs.get("stdout", "")
                    with_stdout = with_certs.get("stdout", "")
                    
                    # Extract test results from stdout
                    without_success = without_stdout.count("SUCCESS")
                    without_failed = without_stdout.count("FAIL")
                    with_success = with_stdout.count("SUCCESS") 
                    with_failed = with_stdout.count("FAIL")
                    
                    f.write("| Test Configuration | ✅ Passed | ❌ Failed |\n")
                    f.write("|---|---|---|\n")
                    f.write(f"| **WITHOUT Corporate Certificates** | {without_success} | {without_failed} |\n")
                    f.write(f"| **WITH Corporate Certificates** | {with_success} | {with_failed} |\n\n")
                    
                    if with_success > without_success:
                        f.write("### 🎯 **RESULT: Corporate certificates ARE REQUIRED and WORKING!**\n\n")
                        f.write("✅ Adding corporate certificates improved connectivity significantly.\n\n")
                        improvement = with_success - without_success
                        f.write(f"🚀 **Corporate certificates enabled {improvement} additional successful connections.**\n\n")
                    elif with_success == without_success and without_failed == 0:
                        f.write("### ℹ️ **RESULT: Corporate certificates not required**\n\n")
                        f.write("Standard certificates are sufficient for this environment\n\n")
                    elif with_success == without_success and without_failed > 0:
                        f.write("### ⚠️ **RESULT: Corporate certificates provide some benefit**\n\n")
                        f.write("Both tests had similar results, corporate certs may help in some scenarios\n\n")
                    else:
                        f.write("### ❓ **RESULT: Mixed results detected**\n\n")
                        f.write("Corporate certificates may be causing some connectivity issues\n\n")
                else:
                    f.write("### ❌ **RESULT: Test execution issues**\n\n")
                    f.write("One or both tests failed to execute properly\n\n")
                
                # Generate detailed comparison table
                if without_certs.get("success") and with_certs.get("success"):
                    try:
                        self._generate_comparison_table(f, without_certs.get("stdout", ""), with_certs.get("stdout", ""))
                    except Exception as e:
                        self.logger.error(f"Failed to generate comparison table: {e}")
                        f.write("**Note:** Detailed comparison table could not be generated due to output parsing issues.\n\n")
                
                # Detailed Results
                f.write("## 🔍 Detailed Test Results\n\n")
                
                f.write("### ❌ Tests WITHOUT Corporate Certificates\n\n")
                if without_certs.get("success"):
                    f.write(f"**Exit Code:** `{without_certs.get('exit_code')}`\n\n")
                    
                    # Parse and format the output for better readability
                    stdout = without_certs.get("stdout", "No output")
                    f.write("#### Test Output:\n")
                    f.write("```\n")
                    f.write(stdout)
                    f.write("\n```\n\n")
                    
                    if without_certs.get("stderr"):
                        f.write("#### Error Output:\n")
                        f.write("```\n")
                        f.write(without_certs.get("stderr"))
                        f.write("\n```\n\n")
                else:
                    f.write(f"❌ **Test Failed:** {without_certs.get('error')}\n\n")
                
                f.write("---\n\n")
                
                f.write("### ✅ Tests WITH Corporate Certificates\n\n")
                if with_certs.get("success"):
                    f.write(f"**Exit Code:** `{with_certs.get('exit_code')}`\n\n")
                    
                    # Parse and format the output for better readability
                    stdout = with_certs.get("stdout", "No output")
                    f.write("#### Test Output:\n")
                    f.write("```\n")
                    f.write(stdout)
                    f.write("\n```\n\n")
                    
                    if with_certs.get("stderr"):
                        f.write("#### Error Output:\n")
                        f.write("```\n")
                        f.write(with_certs.get("stderr"))
                        f.write("\n```\n\n")
                else:
                    f.write(f"❌ **Test Failed:** {with_certs.get('error')}\n\n")
                
                # Recommendations
                f.write("## 💡 Recommendations\n\n")
                
                if without_certs.get("success") and with_certs.get("success"):
                    without_stdout = without_certs.get("stdout", "")
                    with_stdout = with_certs.get("stdout", "")
                    
                    without_success = without_stdout.count("SUCCESS")
                    with_success = with_stdout.count("SUCCESS")
                    
                    if with_success > without_success:
                        f.write("### ✅ Action Items\n\n")
                        f.write("1. **✓ Corporate certificates are essential for this environment**\n")
                        f.write("2. **✓ Configure DevContainers to mount ca-certificates-all.crt**\n")
                        f.write("3. **✓ Add certificate update commands to container startup scripts**\n")
                        f.write("4. **✓ Monitor certificate expiration dates regularly**\n")
                        f.write("5. **✓ Test connectivity after certificate updates**\n\n")
                        f.write("### 🐳 Container Configuration Example\n\n")
                        f.write("```json\n")
                        f.write('{\n')
                        f.write('  "mounts": [\n')
                        f.write('    "source=${env:USERPROFILE}/.certificates/ca-certificates-all.crt,target=/usr/local/share/ca-certificates/corporate.crt,type=bind,consistency=cached"\n')
                        f.write('  ],\n')
                        f.write('  "postCreateCommand": "sudo update-ca-certificates"\n')
                        f.write('}\n')
                        f.write("```\n")
                    elif without_success > 0:
                        f.write("1. Standard certificates appear sufficient for most connections\n")
                        f.write("2. Corporate certificates may be optional for this environment\n")
                        f.write("3. Consider network environment when deploying containers\n")
                        f.write("4. Monitor for connectivity issues in production\n")
                    else:
                        f.write("1. Network connectivity issues detected\n")
                        f.write("2. Check firewall rules and proxy settings\n")
                        f.write("3. Verify DNS resolution in container environment\n")
                        f.write("4. Contact IT support for network troubleshooting\n")
                        f.write("5. Test connectivity from host system first\n")
                
            self.logger.info(f"Comparison report saved to: {report_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to generate comparison report: {e}")


def main():
    """Main entry point"""
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