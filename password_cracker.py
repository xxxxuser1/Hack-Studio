#!/usr/bin/env python3
"""
Password Cracker Module for Ethical Hacking Toolkit
Performs various types of password cracking attacks
"""

import hashlib
import argparse
import itertools
from typing import List, Dict, Optional
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import time


class PasswordCracker:
    def __init__(self, threads: int = 4, hash_type: str = 'md5'):
        self.threads = threads
        self.hash_type = hash_type.lower()
        self.found_passwords = {}
        self.attempts = 0
        self.start_time = None
        
        # Supported hash types
        self.hash_functions = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha224': hashlib.sha224,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512
        }
        
    def hash_password(self, password: str) -> str:
        """Hash a password using the specified algorithm"""
        if self.hash_type not in self.hash_functions:
            raise ValueError(f"Unsupported hash type: {self.hash_type}")
            
        hash_func = self.hash_functions[self.hash_type]
        return hash_func(password.encode()).hexdigest()
        
    def check_password(self, target_hash: str, password: str) -> Optional[str]:
        """Check if a password matches the target hash"""
        self.attempts += 1
        hashed = self.hash_password(password)
        return password if hashed == target_hash else None
        
    def dictionary_attack(self, target_hash: str, wordlist_file: str) -> Optional[str]:
        """Perform dictionary attack using a wordlist file"""
        print(f"[*] Starting dictionary attack on {target_hash}")
        print(f"[*] Hash type: {self.hash_type}")
        print(f"[*] Wordlist: {wordlist_file}")
        
        self.start_time = time.time()
        self.attempts = 0
        
        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[-] Wordlist file not found: {wordlist_file}")
            return None
            
        print(f"[*] Loaded {len(passwords)} passwords from wordlist")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Create tasks
            future_to_password = {
                executor.submit(self.check_password, target_hash, password): password
                for password in passwords
            }
            
            # Check results
            for future in as_completed(future_to_password):
                password = future_to_password[future]
                try:
                    result = future.result()
                    if result:
                        elapsed = time.time() - self.start_time
                        print(f"[+] Password found: {result}")
                        print(f"[+] Time elapsed: {elapsed:.2f} seconds")
                        print(f"[+] Attempts: {self.attempts}")
                        return result
                except Exception as e:
                    print(f"[-] Error checking password {password}: {e}")
                    
        elapsed = time.time() - self.start_time
        print(f"[-] Password not found in wordlist")
        print(f"[-] Time elapsed: {elapsed:.2f} seconds")
        print(f"[-] Attempts: {self.attempts}")
        return None
        
    def brute_force_attack(self, target_hash: str, charset: str, min_length: int, max_length: int) -> Optional[str]:
        """Perform brute force attack"""
        print(f"[*] Starting brute force attack on {target_hash}")
        print(f"[*] Hash type: {self.hash_type}")
        print(f"[*] Charset: {charset}")
        print(f"[*] Length: {min_length}-{max_length}")
        
        self.start_time = time.time()
        self.attempts = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Try different lengths
            for length in range(min_length, max_length + 1):
                print(f"[*] Trying passwords of length {length}")
                
                # Generate all combinations of current length
                for password_tuple in itertools.product(charset, repeat=length):
                    password = ''.join(password_tuple)
                    
                    # Submit for checking
                    future = executor.submit(self.check_password, target_hash, password)
                    try:
                        result = future.result()
                        if result:
                            elapsed = time.time() - self.start_time
                            print(f"[+] Password found: {result}")
                            print(f"[+] Time elapsed: {elapsed:.2f} seconds")
                            print(f"[+] Attempts: {self.attempts}")
                            return result
                    except Exception as e:
                        print(f"[-] Error checking password {password}: {e}")
                        
        elapsed = time.time() - self.start_time
        print(f"[-] Password not found in brute force attack")
        print(f"[-] Time elapsed: {elapsed:.2f} seconds")
        print(f"[-] Attempts: {self.attempts}")
        return None
        
    def rule_based_attack(self, target_hash: str, base_words: List[str], rules: List[str]) -> Optional[str]:
        """Perform rule-based attack"""
        print(f"[*] Starting rule-based attack on {target_hash}")
        print(f"[*] Hash type: {self.hash_type}")
        print(f"[*] Base words: {len(base_words)}")
        print(f"[*] Rules: {len(rules)}")
        
        self.start_time = time.time()
        self.attempts = 0
        
        # Generate password candidates based on rules
        candidates = set()
        
        for word in base_words:
            candidates.add(word)  # Original word
            candidates.add(word.lower())  # Lowercase
            candidates.add(word.upper())  # Uppercase
            candidates.add(word.capitalize())  # Capitalized
            
            # Apply number suffixes
            for i in range(100):
                candidates.add(f"{word}{i}")
                candidates.add(f"{word}{i:02d}")
                
            # Apply common symbols
            symbols = ['!', '@', '#', '$', '%']
            for symbol in symbols:
                candidates.add(f"{word}{symbol}")
                
        print(f"[*] Generated {len(candidates)} password candidates")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Create tasks
            future_to_password = {
                executor.submit(self.check_password, target_hash, password): password
                for password in candidates
            }
            
            # Check results
            for future in as_completed(future_to_password):
                password = future_to_password[future]
                try:
                    result = future.result()
                    if result:
                        elapsed = time.time() - self.start_time
                        print(f"[+] Password found: {result}")
                        print(f"[+] Time elapsed: {elapsed:.2f} seconds")
                        print(f"[+] Attempts: {self.attempts}")
                        return result
                except Exception as e:
                    print(f"[-] Error checking password {password}: {e}")
                    
        elapsed = time.time() - self.start_time
        print(f"[-] Password not found with rule-based attack")
        print(f"[-] Time elapsed: {elapsed:.2f} seconds")
        print(f"[-] Attempts: {self.attempts}")
        return None
        
    def crack_hash_list(self, hash_file: str, wordlist_file: str) -> Dict[str, str]:
        """Crack multiple hashes from a file"""
        print(f"[*] Cracking hashes from {hash_file}")
        print(f"[*] Using wordlist: {wordlist_file}")
        
        try:
            with open(hash_file, 'r') as f:
                hashes = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[-] Hash file not found: {hash_file}")
            return {}
            
        print(f"[*] Loaded {len(hashes)} hashes")
        
        # Load wordlist
        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[-] Wordlist file not found: {wordlist_file}")
            return {}
            
        print(f"[*] Loaded {len(passwords)} passwords from wordlist")
        
        cracked = {}
        self.start_time = time.time()
        self.attempts = 0
        
        # For each hash, try all passwords
        for target_hash in hashes:
            print(f"[*] Cracking hash: {target_hash}")
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                # Create tasks
                future_to_password = {
                    executor.submit(self.check_password, target_hash, password): password
                    for password in passwords
                }
                
                # Check results
                for future in as_completed(future_to_password):
                    password = future_to_password[future]
                    try:
                        result = future.result()
                        if result:
                            cracked[target_hash] = result
                            print(f"[+] {target_hash} -> {result}")
                            break  # Move to next hash
                    except Exception as e:
                        print(f"[-] Error checking password {password}: {e}")
                        
        elapsed = time.time() - self.start_time
        print(f"[*] Finished cracking {len(hashes)} hashes")
        print(f"[*] Successfully cracked: {len(cracked)}")
        print(f"[*] Time elapsed: {elapsed:.2f} seconds")
        print(f"[*] Total attempts: {self.attempts}")
        
        return cracked


def main():
    parser = argparse.ArgumentParser(description='Password Cracker for Ethical Hacking')
    parser.add_argument('hash', nargs='?', help='Target hash to crack')
    parser.add_argument('-t', '--type', default='md5', help='Hash type (md5, sha1, sha256, etc.)')
    parser.add_argument('-w', '--wordlist', help='Wordlist file for dictionary attack')
    parser.add_argument('-b', '--brute-force', action='store_true', help='Perform brute force attack')
    parser.add_argument('--charset', default='abcdefghijklmnopqrstuvwxyz', help='Charset for brute force')
    parser.add_argument('--min-length', type=int, default=1, help='Minimum password length for brute force')
    parser.add_argument('--max-length', type=int, default=6, help='Maximum password length for brute force')
    parser.add_argument('-r', '--rule-based', action='store_true', help='Perform rule-based attack')
    parser.add_argument('--words', nargs='+', help='Base words for rule-based attack')
    parser.add_argument('--hash-file', help='File containing multiple hashes to crack')
    parser.add_argument('--threads', type=int, default=4, help='Number of threads')
    
    args = parser.parse_args()
    
    # Create cracker
    cracker = PasswordCracker(threads=args.threads, hash_type=args.type)
    
    # Handle different attack modes
    if args.hash_file:
        # Crack multiple hashes
        if not args.wordlist:
            print("[-] Wordlist required for hash file cracking")
            return
            
        cracked = cracker.crack_hash_list(args.hash_file, args.wordlist)
        if cracked:
            print("\n[+] CRACKED HASHES:")
            for hash_val, password in cracked.items():
                print(f"  {hash_val} -> {password}")
                
    elif args.hash:
        # Crack single hash
        if args.brute_force:
            # Brute force attack
            cracker.brute_force_attack(
                args.hash, 
                args.charset, 
                args.min_length, 
                args.max_length
            )
        elif args.rule_based:
            # Rule-based attack
            if not args.words:
                print("[-] Base words required for rule-based attack")
                return
            cracker.rule_based_attack(args.hash, args.words, [])
        else:
            # Dictionary attack (default)
            if not args.wordlist:
                print("[-] Wordlist required for dictionary attack")
                return
            cracker.dictionary_attack(args.hash, args.wordlist)
    else:
        print("[-] Either a hash or hash file must be specified")
        parser.print_help()


if __name__ == "__main__":
    main()