# Ethical Hacking Toolkit Usage Guide

## Important Disclaimer

This toolkit is designed for **authorized security testing and educational purposes only**. 
Use only on systems you own or have explicit written permission to test.

Unauthorized access to computer systems is illegal and unethical.

## Installation

1. Run the setup script with administrator privileges:
   ```bash
   # On Windows (as Administrator)
   python setup_toolkit.py
   
   # On Linux/macOS
   sudo python setup_toolkit.py
   ```

2. The setup script will automatically install:
   - Required Python packages
   - System tools (nmap, sqlmap, hydra, etc.)

## Usage

### Command Line Interface

```bash
# Install all dependencies
python hacking_toolkit.py --install

# Network scanning
python hacking_toolkit.py --scan 192.168.1.0/24

# Web application scanning
python hacking_toolkit.py --web http://example.com

# Interactive mode
python hacking_toolkit.py
```

### Interactive Mode Menu

1. **Install All Dependencies** - Install all required tools and packages
2. **Network Scanning** - Discover hosts and services on a network
3. **Web Application Scanning** - Identify vulnerabilities in web applications
4. **Brute Force Attacks** - Test authentication mechanisms
5. **Check Installed Tools** - Verify which tools are available
6. **Exit** - Close the toolkit

## Features

### Network Scanning
- Host discovery using Nmap
- Service detection and version identification
- OS fingerprinting

### Web Application Testing
- Directory and file brute forcing with Gobuster
- Vulnerability scanning with Nikto
- SQL injection testing with SQLmap

### Password Attacks
- Brute force authentication with Hydra
- Password cracking with John the Ripper
- Hash cracking with Hashcat

### Wireless Testing
- WEP/WPA/WPA2 cracking with Aircrack-ng
- WPS brute forcing with Reaver

## Ethical Guidelines

1. Only test systems you own or have explicit permission to test
2. Always obtain written authorization before testing any system
3. Respect privacy and confidentiality of data
4. Report vulnerabilities responsibly
5. Do not use for malicious purposes

## Legal Considerations

- Unauthorized access to computer systems violates computer fraud and abuse laws
- Always follow responsible disclosure practices
- Understand and comply with local laws and regulations

## Troubleshooting

### Common Issues

1. **Permission denied errors**
   - Run with appropriate privileges (Administrator/sudo)
   
2. **Tools not found**
   - Ensure all dependencies are installed
   - Check PATH environment variable

3. **Python package installation failures**
   - Update pip: `python -m pip install --upgrade pip`
   - Check internet connectivity

### Getting Help

For issues with the toolkit, please:
1. Check that all dependencies are properly installed
2. Verify you're running with appropriate privileges
3. Ensure you're using the toolkit ethically and legally