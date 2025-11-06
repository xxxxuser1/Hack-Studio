#!/usr/bin/env python3
"""
Wordlist Generator for Ethical Hacking Toolkit
Generates custom wordlists for brute force attacks
"""

import itertools
import argparse
from typing import List, Set


class WordlistGenerator:
    def __init__(self):
        self.words = []
        self.wordlist = []
        
    def load_base_words(self, filename: str = None, words: List[str] = None):
        """Load base words from file or list"""
        if filename:
            try:
                with open(filename, 'r') as f:
                    self.words = [line.strip() for line in f.readlines() if line.strip()]
                print(f"[+] Loaded {len(self.words)} words from {filename}")
            except FileNotFoundError:
                print(f"[-] File {filename} not found")
                return False
        elif words:
            self.words = words
            print(f"[+] Loaded {len(self.words)} base words")
        else:
            print("[-] No input provided")
            return False
        return True
        
    def generate_combinations(self, max_length: int = 3) -> List[str]:
        """Generate combinations of base words"""
        combinations = []
        
        # Single words
        combinations.extend(self.words)
        
        # Combinations of multiple words
        for length in range(2, min(max_length + 1, len(self.words) + 1)):
            for combo in itertools.combinations_with_replacement(self.words, length):
                combinations.append(''.join(combo))
                # Also add with separator
                combinations.append('_'.join(combo))
                combinations.append('-'.join(combo))
                
        return combinations
        
    def apply_transformations(self, wordlist: List[str]) -> List[str]:
        """Apply common transformations to words"""
        transformed = set()
        
        for word in wordlist:
            # Original word
            transformed.add(word)
            
            # Case variations
            transformed.add(word.lower())
            transformed.add(word.upper())
            transformed.add(word.capitalize())
            
            # Common number additions
            for i in range(0, 100):
                transformed.add(f"{word}{i}")
                transformed.add(f"{i}{word}")
                
            # Common symbol additions
            symbols = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')']
            for symbol in symbols:
                transformed.add(f"{word}{symbol}")
                transformed.add(f"{symbol}{word}")
                
            # Year additions (common years)
            years = ['2020', '2021', '2022', '2023', '2024', '123', '321', '1234', '4321']
            for year in years:
                transformed.add(f"{word}{year}")
                transformed.add(f"{year}{word}")
                
        return list(transformed)
        
    def generate_from_pattern(self, pattern: str) -> List[str]:
        """Generate wordlist from pattern (e.g., prefix@@@)"""
        wordlist = []
        
        if '@@@' in pattern:
            # Replace @@@ with numbers 000-999
            for i in range(1000):
                wordlist.append(pattern.replace('@@@', f"{i:03d}"))
        elif '@@' in pattern:
            # Replace @@ with numbers 00-99
            for i in range(100):
                wordlist.append(pattern.replace('@@', f"{i:02d}"))
        elif '@' in pattern:
            # Replace @ with numbers 0-9
            for i in range(10):
                wordlist.append(pattern.replace('@', str(i)))
                
        return wordlist
        
    def save_wordlist(self, filename: str, wordlist: List[str]):
        """Save wordlist to file"""
        try:
            with open(filename, 'w') as f:
                for word in sorted(set(wordlist)):
                    f.write(f"{word}\n")
            print(f"[+] Wordlist saved to {filename} ({len(set(wordlist))} entries)")
        except Exception as e:
            print(f"[-] Error saving wordlist: {e}")
            
    def generate_common_passwords(self, count: int = 1000) -> List[str]:
        """Generate common password patterns"""
        common = [
            'password', 'admin', 'root', 'user', 'guest',
            'login', 'welcome', '123456', 'qwerty', 'letmein',
            'monkey', 'dragon', 'master', 'hello', 'help',
            'shadow', 'secret', 'test', 'manager', 'account'
        ]
        
        # Add numbers to common passwords
        wordlist = []
        wordlist.extend(common)
        
        for word in common[:20]:  # Limit to first 20 for performance
            for i in range(min(count // 10, 1000)):
                wordlist.append(f"{word}{i}")
                if i < 100:
                    wordlist.append(f"{word}{i:02d}")
                if i < 10:
                    wordlist.append(f"{word}{i:03d}")
                    
        return wordlist


def main():
    parser = argparse.ArgumentParser(description='Wordlist Generator for Ethical Hacking')
    parser.add_argument('-f', '--file', help='Input file with base words')
    parser.add_argument('-w', '--words', nargs='+', help='Base words as arguments')
    parser.add_argument('-o', '--output', default='wordlist.txt', help='Output file')
    parser.add_argument('-c', '--combinations', type=int, default=3, help='Max combination length')
    parser.add_argument('-p', '--pattern', help='Pattern for generation (use @ for digits)')
    parser.add_argument('--common', action='store_true', help='Generate common passwords')
    
    args = parser.parse_args()
    
    generator = WordlistGenerator()
    
    if args.common:
        print("[*] Generating common password wordlist...")
        wordlist = generator.generate_common_passwords()
        generator.save_wordlist(args.output, wordlist)
        return
        
    if args.pattern:
        print(f"[*] Generating wordlist from pattern: {args.pattern}")
        wordlist = generator.generate_from_pattern(args.pattern)
        generator.save_wordlist(args.output, wordlist)
        return
        
    # Load base words
    if not generator.load_base_words(args.file, args.words):
        return
        
    # Generate combinations
    print("[*] Generating combinations...")
    combinations = generator.generate_combinations(args.combinations)
    
    # Apply transformations
    print("[*] Applying transformations...")
    wordlist = generator.apply_transformations(combinations)
    
    # Save wordlist
    generator.save_wordlist(args.output, wordlist)


if __name__ == "__main__":
    main()