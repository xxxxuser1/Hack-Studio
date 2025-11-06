#!/usr/bin/env python3
"""
Ethical Hacking Toolkit - Comprehensive Security Testing Framework

This toolkit is designed for authorized security testing and educational purposes only.
Use only on systems you own or have explicit permission to test.
"""

import sys
import argparse
import subprocess
import os
from typing import List, Dict

# Import configuration
try:
    from config import TOOL_PATHS, WORDLISTS, SCAN_CONFIGS, BANNER, LEGAL_DISCLAIMER
except ImportError:
    print("[-] Config file not found. Using default settings.")
    TOOL_PATHS = {}
    WORDLISTS = {'usernames': [], 'passwords': []}
    SCAN_CONFIGS = {}
    BANNER = "Ethical Hacking Toolkit"
    LEGAL_DISCLAIMER = "Legal disclaimer not available."

class HackingToolkit:
    def __init__(self):
        self.tools = {
            'network_scanning': ['nmap', 'arp-scan'],
            'web_scanning': ['sqlmap', 'nikto', 'gobuster'],
            'password_attacks': ['hydra', 'john', 'hashcat'],
            'wireless_testing': ['aircrack-ng', 'reaver'],
            'exploitation': ['metasploit-framework'],
            'sniffing_spoofing': ['wireshark', 'ettercap'],
            'post_exploitation': ['mimikatz', 'powersploit']
        }
        
    def install_dependencies(self):
        """Install all hacking dependencies"""
        print("[*] Installing hacking dependencies...")
        
        # Install Python packages
        python_packages = [
            'requests',
            'beautifulsoup4',
            'scapy',
            'paramiko',
            'cryptography',
            'pycryptodome',
            'impacket',
            'sqlalchemy',
            'pysnmp',
            'mechanize'
        ]
        
        for package in python_packages:
            try:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
                print(f"[+] Installed Python package: {package}")
            except subprocess.CalledProcessError:
                print(f"[-] Failed to install Python package: {package}")
        
        print("[*] Python dependencies installed successfully!")
        
    def check_tool_installed(self, tool_name: str) -> bool:
        """Check if a tool is installed"""
        try:
            subprocess.check_output(['which', tool_name], stderr=subprocess.DEVNULL)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            try:
                subprocess.check_output(['where', tool_name], stderr=subprocess.DEVNULL, shell=True)
                return True
            except (subprocess.CalledProcessError, FileNotFoundError):
                return False
    
    def run_brute_force(self, target: str, service: str, user_file: str, pass_file: str):
        """Run brute force attack using hydra"""
        print(f"[*] Running brute force attack on {target} ({service})")
        
        if not self.check_tool_installed('hydra'):
            print("[-] Hydra not found. Please install it first.")
            return
            
        cmd = ['hydra', '-L', user_file, '-P', pass_file, service, target]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            print(result.stdout)
            if result.stderr:
                print(f"Errors: {result.stderr}")
        except Exception as e:
            print(f"[-] Error running brute force: {e}")
    
    def scan_network(self, target: str):
        """Scan network using nmap"""
        print(f"[*] Scanning network: {target}")
        
        if not self.check_tool_installed('nmap'):
            print("[-] Nmap not found. Please install it first.")
            return
            
        cmd = ['nmap', '-sS', '-sV', target]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            print(result.stdout)
            if result.stderr:
                print(f"Errors: {result.stderr}")
        except Exception as e:
            print(f"[-] Error running network scan: {e}")
    
    def web_scan(self, url: str):
        """Scan website for vulnerabilities"""
        print(f"[*] Scanning website: {url}")
        
        # Check for required tools
        tools_needed = ['nikto', 'gobuster']
        missing_tools = [tool for tool in tools_needed if not self.check_tool_installed(tool)]
        
        if missing_tools:
            print(f"[-] Missing tools: {', '.join(missing_tools)}. Please install them first.")
            return
            
        # Run nikto scan
        print("[*] Running Nikto scan...")
        nikto_cmd = ['nikto', '-h', url]
        try:
            result = subprocess.run(nikto_cmd, capture_output=True, text=True)
            print(result.stdout)
        except Exception as e:
            print(f"[-] Error running Nikto scan: {e}")
    
    def generate_wordlist(self, output_file: str = "wordlist.txt", words = None):
        """Generate a custom wordlist"""
        try:
            from wordlist_generator import WordlistGenerator
            generator = WordlistGenerator()
            
            if words:
                wordlist = generator.apply_transformations(words)
            else:
                # Generate common passwords
                wordlist = generator.generate_common_passwords(1000)
                
            generator.save_wordlist(output_file, wordlist)
            print(f"[+] Wordlist generated: {output_file}")
        except ImportError:
            print("[-] Wordlist generator module not found")
        except Exception as e:
            print(f"[-] Error generating wordlist: {e}")
    
    def scan_network_range(self, network: str):
        """Scan a network range for active hosts"""
        try:
            from network_scanner import NetworkScanner
            scanner = NetworkScanner()
            results = scanner.scan_network(network)
            scanner.print_results(results)
        except ImportError:
            print("[-] Network scanner module not found")
        except Exception as e:
            print(f"[-] Error scanning network: {e}")
    
    def crack_password_hash(self, hash_value: str, wordlist_file: str, hash_type: str = "md5"):
        """Crack a password hash using a wordlist"""
        try:
            from password_cracker import PasswordCracker
            cracker = PasswordCracker(hash_type=hash_type)
            result = cracker.dictionary_attack(hash_value, wordlist_file)
            if result:
                print(f"[+] Password found: {result}")
            else:
                print("[-] Password not found in wordlist")
        except ImportError:
            print("[-] Password cracker module not found")
        except Exception as e:
            print(f"[-] Error cracking password: {e}")
    
    def show_menu(self):
        """Display the main menu"""
        print("\n" + "="*50)
        print("ETHICAL HACKING TOOLKIT - MAIN MENU")
        print("="*50)
        print("1. Install All Dependencies")
        print("2. Network Scanning")
        print("3. Web Application Scanning")
        print("4. Brute Force Attacks")
        print("5. Generate Wordlist")
        print("6. Scan Network Range")
        print("7. Crack Password Hash")
        print("8. Check Installed Tools")
        print("9. Exit")
        print("-"*50)


def main():
    toolkit = HackingToolkit()
    
    parser = argparse.ArgumentParser(description='Ethical Hacking Toolkit')
    parser.add_argument('--install', action='store_true', help='Install all dependencies')
    parser.add_argument('--scan', type=str, help='Network scan target')
    parser.add_argument('--web', type=str, help='Web scan URL')
    parser.add_argument('--brute', type=str, help='Brute force target')
    
    args = parser.parse_args()
    
    if args.install:
        toolkit.install_dependencies()
        return
        
    if args.scan:
        toolkit.scan_network(args.scan)
        return
        
    if args.web:
        toolkit.web_scan(args.web)
        return
        
    # Interactive mode
    while True:
        toolkit.show_menu()
        choice = input("Select an option (1-9): ").strip()
        
        if choice == '1':
            toolkit.install_dependencies()
            
        elif choice == '2':
            target = input("Enter target IP/range: ").strip()
            if target:
                toolkit.scan_network(target)
                
        elif choice == '3':
            url = input("Enter target URL: ").strip()
            if url:
                toolkit.web_scan(url)
                
        elif choice == '4':
            target = input("Enter target: ").strip()
            service = input("Enter service (ssh, ftp, http-post-form, etc.): ").strip()
            user_file = input("Enter username file path: ").strip()
            pass_file = input("Enter password file path: ").strip()
            
            if all([target, service, user_file, pass_file]):
                toolkit.run_brute_force(target, service, user_file, pass_file)
            else:
                print("[-] All fields are required for brute force attack")
                
        elif choice == '5':
            output_file = input("Enter output file name (default: wordlist.txt): ").strip()
            if not output_file:
                output_file = "wordlist.txt"
            toolkit.generate_wordlist(output_file)
            
        elif choice == '6':
            network = input("Enter network range (e.g., 192.168.1.0/24): ").strip()
            if network:
                toolkit.scan_network_range(network)
                
        elif choice == '7':
            hash_value = input("Enter hash to crack: ").strip()
            wordlist_file = input("Enter wordlist file path: ").strip()
            hash_type = input("Enter hash type (md5, sha1, sha256, etc.): ").strip() or "md5"
            
            if all([hash_value, wordlist_file]):
                toolkit.crack_password_hash(hash_value, wordlist_file, hash_type)
            else:
                print("[-] Hash and wordlist file are required")
                
        elif choice == '8':
            print("[*] Checking installed tools...")
            for category, tools in toolkit.tools.items():
                print(f"\n{category.upper()}:")
                for tool in tools:
                    status = "INSTALLED" if toolkit.check_tool_installed(tool) else "NOT FOUND"
                    print(f"  - {tool}: {status}")
                    
        elif choice == '9':
            print("[*] Exiting Ethical Hacking Toolkit. Goodbye!")
            break
            
        else:
            print("[-] Invalid option. Please select 1-9.")
            
        input("\nPress Enter to continue...")


if __name__ == "__main__":
    main()