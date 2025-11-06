#!/usr/bin/env python3
"""
Web Scanner Module for Ethical Hacking Toolkit
Performs web application vulnerability scanning
"""

import requests
import argparse
import urllib3
import threading
from typing import List, Dict, Set
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
import re


# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WebScanner:
    def __init__(self, threads: int = 10, timeout: int = 10):
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification for testing
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Common directories and files to check
        self.common_paths = [
            # Admin panels
            'admin/', 'admin.php', 'admin.html', 'administrator/', 'login/', 'login.php',
            'wp-admin/', 'wp-login.php', 'dashboard/', 'controlpanel/', 'cpanel/',
            
            # Backup files
            'backup/', 'backup.zip', 'backup.tar.gz', 'config.php.bak', 'config.php~',
            '.env', '.git/config', '.htaccess', 'web.config',
            
            # Common files
            'robots.txt', 'sitemap.xml', 'README.md', 'readme.html',
            
            # API endpoints
            'api/', 'api/v1/', 'api/v2/', 'graphql', 'swagger/',
            
            # Development files
            'debug.php', 'test.php', 'phpinfo.php', 'info.php'
        ]
        
        # Vulnerability patterns
        self.vuln_patterns = {
            'SQL Injection': [
                r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result",
                r"MySqlClient\.", r"PostgreSQL.*ERROR", r"Warning.*pg_.*",
                r"ORA-[0-9]{5}", r"Microsoft SQL Native Client error"
            ],
            'XSS': [
                r"<script>alert\(", r"on\w+\s*=", r"javascript:",
                r"<iframe", r"<object", r"<embed"
            ],
            'LFI': [
                r"root:.*:0:0:", r"boot loader", r"system preferences"
            ]
        }
        
    def check_url(self, base_url: str, path: str) -> Dict:
        """Check if a URL path exists"""
        url = urljoin(base_url, path)
        try:
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                return {
                    'url': url,
                    'status_code': response.status_code,
                    'size': len(response.content),
                    'title': self.extract_title(response.text)
                }
            elif response.status_code in [301, 302, 401, 403]:
                return {
                    'url': url,
                    'status_code': response.status_code,
                    'redirect': response.headers.get('Location', '')
                }
        except requests.exceptions.RequestException:
            pass
        return None
        
    def extract_title(self, html: str) -> str:
        """Extract title from HTML"""
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else "No title"
        
    def directory_bruteforce(self, base_url: str, wordlist: List[str] = None) -> List[Dict]:
        """Brute force directories and files"""
        if wordlist is None:
            wordlist = self.common_paths
            
        print(f"[*] Brute forcing {len(wordlist)} paths on {base_url}")
        
        found_paths = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Create tasks
            future_to_path = {
                executor.submit(self.check_url, base_url, path): path
                for path in wordlist
            }
            
            # Collect results
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    result = future.result()
                    if result:
                        found_paths.append(result)
                        status = result.get('status_code', 'N/A')
                        size = result.get('size', 'N/A')
                        print(f"[+] {result['url']} (Status: {status}, Size: {size})")
                except Exception as e:
                    print(f"[-] Error checking {path}: {e}")
                    
        return found_paths
        
    def check_vulnerabilities(self, url: str) -> Dict:
        """Check for common web vulnerabilities"""
        vulnerabilities = {}
        
        # Test payloads for different vulnerabilities
        payloads = {
            'SQL Injection': ["'", "' OR '1'='1", "1' ORDER BY 1--+", "1' UNION SELECT NULL--+"],
            'XSS': ["<script>alert(1)</script>", "javascript:alert(1)", "'\"><script>alert(1)</script>"]
        }
        
        for vuln_type, payload_list in payloads.items():
            vulnerabilities[vuln_type] = []
            
            for payload in payload_list:
                # Test with GET parameters
                try:
                    test_url = f"{url}?test={payload}"
                    response = self.session.get(test_url, timeout=self.timeout)
                    
                    # Check for vulnerability patterns
                    for pattern in self.vuln_patterns.get(vuln_type, []):
                        if re.search(pattern, response.text, re.IGNORECASE):
                            vulnerabilities[vuln_type].append({
                                'payload': payload,
                                'url': test_url,
                                'evidence': pattern
                            })
                            break
                except:
                    pass
                    
        return {k: v for k, v in vulnerabilities.items() if v}  # Remove empty lists
        
    def scan_headers(self, url: str) -> Dict:
        """Scan HTTP headers for security issues"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            headers = response.headers
            
            issues = {}
            
            # Check security headers
            if 'X-Frame-Options' not in headers:
                issues['Missing X-Frame-Options'] = 'Clickjacking protection missing'
                
            if 'X-Content-Type-Options' not in headers:
                issues['Missing X-Content-Type-Options'] = 'MIME-sniffing protection missing'
                
            if 'X-XSS-Protection' not in headers:
                issues['Missing X-XSS-Protection'] = 'Legacy XSS protection missing'
                
            if 'Strict-Transport-Security' not in headers:
                issues['Missing HSTS'] = 'HTTP Strict Transport Security missing'
                
            if headers.get('Server'):
                issues['Server Disclosure'] = f"Server header reveals: {headers['Server']}"
                
            return issues
        except Exception as e:
            return {'Error': str(e)}
            
    def scan_website(self, url: str, check_vulns: bool = False, check_headers: bool = True) -> Dict:
        """Complete website scan"""
        print(f"[*] Starting web scan for {url}")
        start_time = time.time()
        
        results = {
            'url': url,
            'directories': [],
            'vulnerabilities': {},
            'header_issues': {}
        }
        
        # Directory brute force
        results['directories'] = self.directory_bruteforce(url)
        
        # Vulnerability scanning
        if check_vulns:
            print("[*] Checking for vulnerabilities...")
            results['vulnerabilities'] = self.check_vulnerabilities(url)
            
        # Header scanning
        if check_headers:
            print("[*] Checking HTTP headers...")
            results['header_issues'] = self.scan_headers(url)
            
        end_time = time.time()
        print(f"[*] Web scan completed in {end_time - start_time:.2f} seconds")
        
        return results
        
    def print_results(self, results: Dict):
        """Print formatted scan results"""
        print("\n" + "="*70)
        print(f"WEB SCAN RESULTS FOR {results['url']}")
        print("="*70)
        
        # Directory results
        if results['directories']:
            print(f"\n[+] DISCOVERED DIRECTORIES AND FILES ({len(results['directories'])}):")
            print("-" * 50)
            for item in results['directories']:
                url = item['url']
                status = item.get('status_code', 'N/A')
                size = item.get('size', 'N/A')
                title = item.get('title', '')
                redirect = item.get('redirect', '')
                
                if title:
                    print(f"  {url} (Status: {status}, Size: {size}) - {title}")
                elif redirect:
                    print(f"  {url} (Status: {status}) -> {redirect}")
                else:
                    print(f"  {url} (Status: {status}, Size: {size})")
        else:
            print("\n[-] No directories or files discovered")
            
        # Vulnerability results
        if results['vulnerabilities']:
            print(f"\n[+] VULNERABILITIES FOUND:")
            print("-" * 30)
            for vuln_type, instances in results['vulnerabilities'].items():
                print(f"\n  {vuln_type}:")
                for instance in instances:
                    print(f"    Payload: {instance['payload']}")
                    print(f"    URL: {instance['url']}")
        else:
            print("\n[-] No vulnerabilities found")
            
        # Header issues
        if results['header_issues']:
            print(f"\n[+] HTTP HEADER ISSUES:")
            print("-" * 25)
            for issue, description in results['header_issues'].items():
                print(f"  {issue}: {description}")
        else:
            print("\n[+] No HTTP header issues found")


def main():
    parser = argparse.ArgumentParser(description='Web Scanner for Ethical Hacking')
    parser.add_argument('url', help='Target URL (e.g., http://example.com)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('--vulns', action='store_true', help='Check for vulnerabilities')
    parser.add_argument('--no-headers', action='store_true', help='Skip header checks')
    
    args = parser.parse_args()
    
    # Validate URL
    parsed = urlparse(args.url)
    if not parsed.scheme:
        args.url = 'http://' + args.url
        
    # Create scanner
    scanner = WebScanner(threads=args.threads, timeout=args.timeout)
    
    # Perform scan
    results = scanner.scan_website(
        args.url, 
        check_vulns=args.vulns,
        check_headers=not args.no_headers
    )
    
    # Print results
    scanner.print_results(results)


if __name__ == "__main__":
    main()