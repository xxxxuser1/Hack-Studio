#!/usr/bin/env python3
"""
Network Scanner Module for Ethical Hacking Toolkit
Performs network discovery and port scanning
"""

import socket
import threading
import argparse
from typing import List, Dict, Tuple
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


class NetworkScanner:
    def __init__(self, threads: int = 100, timeout: float = 1.0):
        self.threads = threads
        self.timeout = timeout
        self.open_ports = {}
        self.active_hosts = []
        
    def ping_host(self, ip: str) -> bool:
        """Ping a host to check if it's alive"""
        try:
            # Try to create a connection to port 80 (HTTP)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, 80))
            sock.close()
            
            # If connection successful or refused, host is alive
            return result == 0 or result == 111  # 111 = Connection refused (port closed but host alive)
        except:
            return False
            
    def scan_port(self, ip: str, port: int) -> bool:
        """Scan a single port on a host"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
            
    def scan_ports(self, ip: str, port_range: Tuple[int, int] = (1, 1000)) -> List[int]:
        """Scan ports on a host"""
        open_ports = []
        
        print(f"[*] Scanning {ip} ports {port_range[0]}-{port_range[1]}")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Create port scan tasks
            future_to_port = {
                executor.submit(self.scan_port, ip, port): port 
                for port in range(port_range[0], port_range[1] + 1)
            }
            
            # Collect results
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        open_ports.append(port)
                        print(f"[+] Port {port} is open on {ip}")
                except Exception as e:
                    print(f"[-] Error scanning port {port}: {e}")
                    
        return sorted(open_ports)
        
    def discover_hosts(self, network: str) -> List[str]:
        """Discover active hosts on a network"""
        active_hosts = []
        
        # Parse network (e.g., 192.168.1.0/24)
        if '/' in network:
            base_ip, subnet = network.split('/')
            subnet = int(subnet)
            
            # For simplicity, handle /24 networks
            if subnet == 24:
                base_parts = base_ip.split('.')
                base_network = '.'.join(base_parts[:-1])  # e.g., 192.168.1
                
                print(f"[*] Discovering hosts on {network}")
                
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    # Create ping tasks for all IPs in range
                    future_to_ip = {
                        executor.submit(self.ping_host, f"{base_network}.{i}"): f"{base_network}.{i}"
                        for i in range(1, 255)
                    }
                    
                    # Collect results
                    for future in as_completed(future_to_ip):
                        ip = future_to_ip[future]
                        try:
                            if future.result():
                                active_hosts.append(ip)
                                print(f"[+] Host found: {ip}")
                        except Exception as e:
                            print(f"[-] Error pinging {ip}: {e}")
                            
        else:
            # Single IP
            if self.ping_host(network):
                active_hosts.append(network)
                print(f"[+] Host found: {network}")
                
        return sorted(active_hosts)
        
    def get_service_name(self, port: int) -> str:
        """Get service name for a port"""
        try:
            return socket.getservbyport(port)
        except:
            service_map = {
                21: 'FTP',
                22: 'SSH',
                23: 'Telnet',
                25: 'SMTP',
                53: 'DNS',
                80: 'HTTP',
                110: 'POP3',
                143: 'IMAP',
                443: 'HTTPS',
                993: 'IMAPS',
                995: 'POP3S'
            }
            return service_map.get(port, 'Unknown')
            
    def scan_network(self, network: str, port_range: Tuple[int, int] = (1, 1000)) -> Dict[str, List[int]]:
        """Complete network scan"""
        print(f"[*] Starting network scan for {network}")
        start_time = time.time()
        
        # Discover active hosts
        active_hosts = self.discover_hosts(network)
        print(f"[+] Found {len(active_hosts)} active hosts")
        
        # Scan ports for each active host
        results = {}
        for host in active_hosts:
            open_ports = self.scan_ports(host, port_range)
            if open_ports:
                results[host] = open_ports
                print(f"[+] {host}: {len(open_ports)} open ports")
                
        end_time = time.time()
        print(f"[*] Scan completed in {end_time - start_time:.2f} seconds")
        
        return results
        
    def print_results(self, results: Dict[str, List[int]]):
        """Print formatted scan results"""
        if not results:
            print("[-] No open ports found")
            return
            
        print("\n" + "="*60)
        print("NETWORK SCAN RESULTS")
        print("="*60)
        
        for host, ports in results.items():
            print(f"\nHost: {host}")
            print("-" * 30)
            for port in ports:
                service = self.get_service_name(port)
                print(f"  Port {port:>5}: {service}")


def main():
    parser = argparse.ArgumentParser(description='Network Scanner for Ethical Hacking')
    parser.add_argument('network', help='Network to scan (e.g., 192.168.1.0/24 or 192.168.1.1)')
    parser.add_argument('-p', '--ports', default='1-1000', help='Port range (e.g., 1-1000 or 22,80,443)')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Number of threads')
    parser.add_argument('--timeout', type=float, default=1.0, help='Timeout for connections')
    
    args = parser.parse_args()
    
    # Parse port range
    if '-' in args.ports:
        start, end = map(int, args.ports.split('-'))
        port_range = (start, end)
    elif ',' in args.ports:
        # Specific ports
        ports = list(map(int, args.ports.split(',')))
        # For simplicity, we'll scan the range from min to max
        port_range = (min(ports), max(ports))
    else:
        port_range = (1, int(args.ports))
        
    # Create scanner
    scanner = NetworkScanner(threads=args.threads, timeout=args.timeout)
    
    # Perform scan
    results = scanner.scan_network(args.network, port_range)
    
    # Print results
    scanner.print_results(results)


if __name__ == "__main__":
    main()