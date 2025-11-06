#!/usr/bin/env python3
"""
Main Launcher for Ethical Hacking Toolkit
Centralized interface for all toolkit modules
"""

import sys
import os
import argparse
import subprocess
from pathlib import Path


# Add current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))


def show_banner():
    """Display toolkit banner"""
    banner = r'''
  ______ _   _  _____ _____ ____  _   _ _______ ______ 
 |  ____| \ | |/ ____|_   _/ __ \| \ | |__   __|  ____|
 | |__  |  \| | |      | || |  | |  \| |  | |  | |__   
 |  __| | . ` | |      | || |  | | . ` |  | |  |  __|  
 | |____| |\  | |____ _| || |__| | |\  |  | |  | |____ 
 |______|_| \_|\_____|\____/ \____/|_| \_|  |_|  |______|
                                                       
  _____ _    _  _____ _    _  _______ ____  _____  __  __ 
 |_   _| |  | |/ ____| |  | |/ /_   _/ __ \|  __ \|  \/  |
   | | | |__| | |    | |  | | '_ \| || |  | | |__) | \  / |
   | | |  __  | |    | |  | | (_) | || |  | |  _  /| |\/| |
  _| |_| |  | | |____| |__| | (_)_| || |__| | | \ \| |  | |
 |_____|_|  |_|\_____|\____/ \___/_____\____/|_|  \_\_|  |_|
                                                           
============================================================
      ETHICAL HACKING TOOLKIT - AUTHORIZED USE ONLY
============================================================
    '''
    print(banner)


def run_module(module_name: str, args: list = None):
    """Run a specific toolkit module"""
    module_map = {
        'main': 'hacking_toolkit.py',
        'setup': 'setup_toolkit.py',
        'wordlist': 'wordlist_generator.py',
        'network': 'network_scanner.py',
        'web': 'web_scanner.py',
        'password': 'password_cracker.py',
        'report': 'report_generator.py'
    }
    
    if module_name not in module_map:
        print(f"[-] Unknown module: {module_name}")
        return
        
    module_file = module_map[module_name]
    module_path = os.path.join(os.path.dirname(__file__), module_file)
    
    if not os.path.exists(module_path):
        print(f"[-] Module file not found: {module_path}")
        return
        
    # Build command
    cmd = [sys.executable, module_path]
    if args:
        cmd.extend(args)
        
    # Run module
    try:
        subprocess.run(cmd)
    except Exception as e:
        print(f"[-] Error running module {module_name}: {e}")


def show_menu():
    """Display the main menu"""
    print("\n" + "="*60)
    print("ETHICAL HACKING TOOLKIT - MAIN MENU")
    print("="*60)
    print("1. Main Toolkit Interface")
    print("2. Setup/Install Dependencies")
    print("3. Wordlist Generator")
    print("4. Network Scanner")
    print("5. Web Application Scanner")
    print("6. Password Cracker")
    print("7. Report Generator")
    print("8. Exit")
    print("-"*60)


def interactive_mode():
    """Run in interactive mode"""
    while True:
        show_menu()
        choice = input("Select an option (1-8): ").strip()
        
        if choice == '1':
            run_module('main')
        elif choice == '2':
            run_module('setup')
        elif choice == '3':
            run_module('wordlist')
        elif choice == '4':
            run_module('network')
        elif choice == '5':
            run_module('web')
        elif choice == '6':
            run_module('password')
        elif choice == '7':
            run_module('report')
        elif choice == '8':
            print("[*] Exiting Ethical Hacking Toolkit. Goodbye!")
            break
        else:
            print("[-] Invalid option. Please select 1-8.")
            
        input("\nPress Enter to continue...")


def main():
    parser = argparse.ArgumentParser(description='Ethical Hacking Toolkit Launcher')
    parser.add_argument('module', nargs='?', help='Module to run (main, setup, wordlist, network, web, password, report)')
    parser.add_argument('args', nargs=argparse.REMAINDER, help='Arguments to pass to the module')
    
    args = parser.parse_args()
    
    show_banner()
    
    if args.module:
        # Run specific module
        run_module(args.module, args.args)
    else:
        # Interactive mode
        interactive_mode()


if __name__ == "__main__":
    main()