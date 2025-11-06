#!/usr/bin/env python3
"""
Setup script for Ethical Hacking Toolkit
Installs all required dependencies and tools
"""

import os
import sys
import platform
import subprocess
from pathlib import Path


def check_admin_privileges():
    """Check if the script is running with admin privileges"""
    try:
        if platform.system().lower() == 'windows':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            return os.geteuid() == 0
    except:
        return False


def install_python_packages():
    """Install required Python packages"""
    print("[*] Installing Python packages...")
    
    packages = [
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
    
    for package in packages:
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
            print(f"[+] Installed {package}")
        except subprocess.CalledProcessError:
            print(f"[-] Failed to install {package}")


def install_system_packages_windows():
    """Install system packages on Windows using Chocolatey"""
    print("[*] Installing system packages on Windows...")
    
    # Check if Chocolatey is installed
    try:
        subprocess.check_output(['choco', '--version'], stderr=subprocess.DEVNULL)
        print("[+] Chocolatey found")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[-] Chocolatey not found. Installing Chocolatey first...")
        # Install Chocolatey
        choco_install_cmd = [
            'powershell', '-Command',
            "Set-ExecutionPolicy Bypass -Scope Process -Force; "
            "[System.Net.ServicePointManager]::SecurityProtocol = "
            "[System.Net.ServicePointManager]::SecurityProtocol -bor 3072; "
            "iex ((New-Object System.Net.WebClient).DownloadString("
            "'https://community.chocolatey.org/install.ps1'))"
        ]
        
        try:
            subprocess.run(choco_install_cmd, check=True, shell=True)
            print("[+] Chocolatey installed successfully")
        except subprocess.CalledProcessError:
            print("[-] Failed to install Chocolatey")
            return
    
    # Install hacking tools using Chocolatey
    tools = [
        'nmap',
        'wireshark',
        'sqlmap',
        'nikto',
        'hydra'
    ]
    
    for tool in tools:
        try:
            subprocess.check_call(['choco', 'install', tool, '-y'])
            print(f"[+] Installed {tool}")
        except subprocess.CalledProcessError:
            print(f"[-] Failed to install {tool}")


def install_system_packages_linux():
    """Install system packages on Linux"""
    print("[*] Installing system packages on Linux...")
    
    # Update package list
    try:
        subprocess.check_call(['sudo', 'apt', 'update'])
    except subprocess.CalledProcessError:
        print("[-] Failed to update package list")
        return
    
    # Install tools
    tools = [
        'nmap',
        'wireshark',
        'sqlmap',
        'nikto',
        'hydra',
        'john',
        'gobuster',
        'metasploit-framework'
    ]
    
    for tool in tools:
        try:
            subprocess.check_call(['sudo', 'apt', 'install', '-y', tool])
            print(f"[+] Installed {tool}")
        except subprocess.CalledProcessError:
            print(f"[-] Failed to install {tool}")


def install_system_packages_mac():
    """Install system packages on macOS using Homebrew"""
    print("[*] Installing system packages on macOS...")
    
    # Check if Homebrew is installed
    try:
        subprocess.check_output(['brew', '--version'], stderr=subprocess.DEVNULL)
        print("[+] Homebrew found")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[-] Homebrew not found. Please install Homebrew first:")
        print("   /bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"")
        return
    
    # Install tools
    tools = [
        'nmap',
        'wireshark',
        'sqlmap',
        'nikto',
        'hydra',
        'john',
        'metasploit'
    ]
    
    for tool in tools:
        try:
            subprocess.check_call(['brew', 'install', tool])
            print(f"[+] Installed {tool}")
        except subprocess.CalledProcessError:
            print(f"[-] Failed to install {tool}")


def main():
    print("ETHICAL HACKING TOOLKIT SETUP")
    print("=" * 40)
    
    # Check admin privileges
    if not check_admin_privileges():
        print("[-] This script requires administrator privileges")
        if platform.system().lower() == 'windows':
            print("   Please run this script as Administrator")
        else:
            print("   Please run this script with sudo")
        return
    
    # Install Python packages
    install_python_packages()
    
    # Install system packages based on OS
    system = platform.system().lower()
    if system == 'windows':
        install_system_packages_windows()
    elif system == 'linux':
        install_system_packages_linux()
    elif system == 'darwin':  # macOS
        install_system_packages_mac()
    else:
        print(f"[-] Unsupported operating system: {system}")
        return
    
    print("\n[+] Setup completed!")
    print("[*] You can now run the hacking toolkit with:")
    print("    python hacking_toolkit.py")


if __name__ == "__main__":
    main()