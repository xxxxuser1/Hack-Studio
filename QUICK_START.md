# Quick Start Guide - Ethical Hacking Toolkit

## Prerequisites

- Python 3.6 or higher
- Administrator privileges (for tool installation)
- Internet connection (for downloading dependencies)

## Installation

1. **Run the setup script** (with admin privileges):
   ```bash
   # Windows (run as Administrator)
   python setup_toolkit.py
   
   # Linux/macOS
   sudo python setup_toolkit.py
   ```

2. **Verify installation**:
   ```bash
   python hacking_toolkit.py --help
   ```

## Quick Usage Examples

### 1. Interactive Mode
Launch the full toolkit interface:
```bash
python hacking_toolkit.py
```

### 2. Install All Dependencies
```bash
python hacking_toolkit.py --install
```

### 3. Network Scanning
```bash
python hacking_toolkit.py --scan 192.168.1.0/24
```

### 4. Web Application Scanning
```bash
python hacking_toolkit.py --web http://example.com
```

### 5. Using Individual Modules
```bash
# Generate a wordlist
python wordlist_generator.py --common -o passwords.txt

# Scan a network
python network_scanner.py 192.168.1.0/24

# Scan a web application
python web_scanner.py http://example.com --vulns

# Crack a password hash
python password_cracker.py --hash-file hashes.txt -w passwords.txt

# Generate a report
python report_generator.py --target http://example.com --tester "Your Name" --format html
```

## Using the Toolkit Launcher

The centralized launcher provides access to all modules:
```bash
# Launch interactive mode
python toolkit_launcher.py

# Run specific modules
python toolkit_launcher.py network 192.168.1.0/24
python toolkit_launcher.py web http://example.com
python toolkit_launcher.py password --hash-file hashes.txt -w wordlist.txt
```

## Platform-Specific Launchers

### Windows
```bash
run_toolkit.bat
```

### Linux/macOS
```bash
chmod +x run_toolkit.sh
./run_toolkit.sh
```

## Ethical Guidelines

1. **Only test systems you own** or have explicit written permission to test
2. **Always obtain proper authorization** before security testing
3. **Respect privacy** and handle sensitive data appropriately
4. **Follow responsible disclosure** practices for any vulnerabilities found
5. **Comply with all applicable laws** and regulations

## Troubleshooting

### Common Issues

1. **Permission errors during setup**
   - Ensure you're running with administrator privileges
   - On Linux/macOS, use `sudo`

2. **Tools not found**
   - Verify all dependencies were installed successfully
   - Check that tools are in your system PATH

3. **Python import errors**
   - Ensure all Python packages were installed
   - Run `pip install -r requirements.txt`

### Getting Help

For detailed usage instructions, refer to:
- `USAGE.md` - Basic usage guide
- `TOOLKIT_DOCS.md` - Comprehensive documentation
- `SUMMARY.md` - Project overview

## Legal Reminder

UNAUTHORIZED ACCESS TO COMPUTER SYSTEMS IS ILLEGAL. 
This toolkit is for AUTHORIZED security testing and EDUCATIONAL purposes only.

By using this toolkit, you agree to:
- Only test systems you own or have explicit permission to test
- Comply with all applicable laws and regulations
- Use the toolkit responsibly and ethically