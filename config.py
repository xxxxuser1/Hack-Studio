#!/usr/bin/env python3
"""
Configuration file for Ethical Hacking Toolkit
"""

# Default settings
DEFAULT_TIMEOUT = 30
DEFAULT_THREADS = 10
DEFAULT_DELAY = 0.5

# Tool paths (will be auto-detected if empty)
TOOL_PATHS = {
    'nmap': '',
    'hydra': '',
    'sqlmap': '',
    'nikto': '',
    'gobuster': '',
    'john': '',
    'hashcat': '',
    'wireshark': ''
}

# Wordlists for brute force attacks
WORDLISTS = {
    'usernames': [
        'admin',
        'root',
        'user',
        'test',
        'guest',
        'administrator',
        'manager',
        'operator'
    ],
    'passwords': [
        'password',
        'admin',
        'root',
        '123456',
        'password123',
        'admin123',
        'qwerty',
        'letmein'
    ]
}

# Scan configurations
SCAN_CONFIGS = {
    'nmap': {
        'fast_scan': '-F',
        'service_detection': '-sV',
        'os_detection': '-O',
        'default_script': '-sC'
    },
    'gobuster': {
        'wordlist': '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
        'extensions': 'php,html,txt,xml,json',
        'status_codes': '200,204,301,302,307,401,403'
    }
}

# Output settings
OUTPUT_DIR = './output'
LOG_FILE = './logs/toolkit.log'
SAVE_RESULTS = True

# Legal disclaimer
LEGAL_DISCLAIMER = """
ETHICAL HACKING TOOLKIT - LEGAL DISCLAIMER

This toolkit is designed for AUTHORIZED security testing and EDUCATIONAL purposes only.
Using this toolkit on systems without explicit permission is ILLEGAL and UNETHICAL.

By using this toolkit, you agree to:
1. Only test systems you own or have written permission to test
2. Comply with all applicable laws and regulations
3. Use the toolkit responsibly and ethically
4. Not use it for any malicious or unauthorized purposes

THE CREATOR OF THIS TOOLKIT IS NOT RESPONSIBLE FOR ANY MISUSE OR DAMAGES CAUSED BY THIS SOFTWARE.
"""

# Banner for the toolkit
BANNER = r'''
  ______ _   _  _____ _____ ____  _   _ _______ ______ 
 |  ____| \ | |/ ____|_   _/ __ \| \ | |__   __|  ____|
 | |__  |  \| | |      | || |  | |  \| |  | |  | |__   
 |  __| | . ` | |      | || |  | | . ` |  | |  |  __|  
 | |____| |\  | |____ _| || |__| | |\  |  | |  | |____ 
 |______|_| \_|\_____|_____\____/|_| \_|  |_|  |______|
                                                       
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