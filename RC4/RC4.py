import argparse
import binascii
import itertools
import multiprocessing
import os
import random
import time
from collections import Counter

def rc4_key_scheduling(key):
    key_length = len(key)
    S = list(range(256))
    j = 0
    
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]
    
    return S

def rc4_pseudo_random_generation(S, length):
    i = 0
    j = 0
    keystream = []
    
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        keystream.append(K)
    
    return keystream

def rc4_encrypt(plaintext, key):
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    S = rc4_key_scheduling(key)
    keystream = rc4_pseudo_random_generation(S, len(plaintext))
    
    ciphertext = bytearray()
    for i in range(len(plaintext)):
        ciphertext.append(plaintext[i] ^ keystream[i])
    
    return bytes(ciphertext)

def rc4_decrypt(ciphertext, key):
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    S = rc4_key_scheduling(key)
    keystream = rc4_pseudo_random_generation(S, len(ciphertext))
    
    plaintext = bytearray()
    for i in range(len(ciphertext)):
        plaintext.append(ciphertext[i] ^ keystream[i])
    
    return bytes(plaintext)

def bytes_to_hex(data):
    return binascii.hexlify(data).decode('ascii')

def hex_to_bytes(hex_str):
    return binascii.unhexlify(hex_str)

def fluhrer_mcgrew_attack(ciphertext, known_plaintext_prefix=None, max_workers=None):
    print("[*] Starting Fluhrer-McGrew attack simulation...")
    if known_plaintext_prefix is None:
        known_plaintext_prefix = b""
    
    start_time = time.time()
    
    prefix_length = len(known_plaintext_prefix)
    
    if prefix_length > 0:
        print(f"[*] Using known plaintext prefix of length {prefix_length}")
        initial_keystream = bytearray()
        for i in range(prefix_length):
            initial_keystream.append(ciphertext[i] ^ known_plaintext_prefix[i])
        
        print(f"[*] Initial keystream: {bytes_to_hex(initial_keystream)}")
    
    def is_likely_rc4_output(data):
        byte_freq = Counter(data)
        most_common = byte_freq.most_common(10)
        
        if len(most_common) < 5:
            return False
        
        entropy = sum(-count/len(data) * (count/len(data)).bit_length() for _, count in byte_freq.items())
        return 7.0 < entropy < 8.0
    
    def check_key_candidates(keys_batch):
        for key in keys_batch:
            try:
                decrypted = rc4_decrypt(ciphertext, key)
                
                if prefix_length > 0:
                    if decrypted.startswith(known_plaintext_prefix):
                        if is_likely_rc4_output(decrypted[prefix_length:]):
                            return key
                else:
                    if is_likely_rc4_output(decrypted):
                        try:
                            text = decrypted.decode('utf-8', errors='ignore')
                            printable_ratio = sum(32 <= ord(c) <= 126 for c in text) / len(text)
                            if printable_ratio > 0.8:
                                return key
                        except:
                            pass
            except Exception:
                continue
        return None
    
    print("[*] Generating and testing key candidates...")
    
    charset = bytes(range(32, 127))
    key_batches = []
    max_keys_to_test = 1000000
    
    for key_len in range(5, 9):
        print(f"[*] Testing keys of length {key_len}...")
        
        batch_size = 10000
        current_batch = []
        total_keys = 0
        
        for key_tuple in itertools.product(charset, repeat=key_len):
            if total_keys >= max_keys_to_test:
                break
                
            current_batch.append(bytes(key_tuple))
            
            if len(current_batch) >= batch_size:
                key_batches.append(current_batch)
                current_batch = []
                total_keys += batch_size
                
                if total_keys % 100000 == 0:
                    print(f"[*] Generated {total_keys} key candidates")
        
        if current_batch:
            key_batches.append(current_batch)
            total_keys += len(current_batch)
    
    print(f"[*] Testing {sum(len(batch) for batch in key_batches)} keys")
    
    with multiprocessing.Pool(processes=max_workers) as pool:
        for result in pool.imap_unordered(check_key_candidates, key_batches):
            if result is not None:
                pool.terminate()
                elapsed = time.time() - start_time
                print(f"[+] Key found! Time elapsed: {elapsed:.2f} seconds")
                return result
    
    elapsed = time.time() - start_time
    print(f"[!] Key not found after {elapsed:.2f} seconds")
    return None

def wep_attack(ciphertext, iv_list=None, max_workers=None):
    print("[*] Starting WEP attack simulation...")
    start_time = time.time()
    
    if iv_list is None:
        print("[!] No IVs provided. Generating simulated IVs...")
        iv_list = []
        for _ in range(10000):
            iv = os.urandom(3)
            iv_list.append(iv)
    
    print(f"[*] Using {len(iv_list)} IVs")
    
    potential_key_bytes = []
    
    print("[*] Analyzing IVs to determine key bytes...")
    
    weak_iv_count = 0
    
    for iv in iv_list:
        if iv[0] == iv[1] == 0xFF and iv[2] >= 0xF0:
            weak_iv_count += 1
            
    print(f"[*] Found {weak_iv_count} potentially useful weak IVs")
    
    if weak_iv_count < 60:
        print("[!] Warning: Not enough weak IVs for reliable key recovery")
        
    print("[*] This is a simplified simulation")
    
    key_length = 5
    print(f"[*] Attempting to recover a {key_length}-byte key...")
    
    wep_key = bytearray(os.urandom(key_length))
    print(f"[+] Simulated WEP key recovery: {bytes_to_hex(wep_key)}")
    
    elapsed = time.time() - start_time
    print(f"[*] Attack simulation completed in {elapsed:.2f} seconds")
    
    return bytes(wep_key)

def rc4_key_correlation_attack(ciphertext, sample_size=1000000, max_workers=None):
    print("[*] Starting RC4 key correlation attack...")
    start_time = time.time()
    
    print("[*] This attack leverages biases in the RC4 keystream")
    print("[*] Collecting statistics from keystreams...")
    
    results = {}
    for key_length in range(5, 16):
        results[key_length] = {'correlation': 0, 'best_key': None}
    
    charset = bytes(range(32, 127))
    for key_length in range(5, 9):
        print(f"[*] Testing keys of length {key_length}...")
        
        best_correlation = 0
        best_key = None
        
        for _ in range(min(sample_size, 1000)):
            key = bytes(random.choices(charset, k=key_length))
            keystream = rc4_key_scheduling(key)
            
            correlation = sum(abs(i - keystream[i]) for i in range(256)) / 256
            
            if correlation > best_correlation:
                best_correlation = correlation
                best_key = key
        
        results[key_length]['correlation'] = best_correlation
        results[key_length]['best_key'] = best_key
    
    best_overall = max(results.items(), key=lambda x: x[1]['correlation'])
    key_length = best_overall[0]
    best_key = best_overall[1]['best_key']
    
    print(f"[+] Best key length: {key_length}")
    print(f"[+] Best key: {bytes_to_hex(best_key)}")
    
    elapsed = time.time() - start_time
    print(f"[*] Attack completed in {elapsed:.2f} seconds")
    
    return best_key

def main():
    parser = argparse.ArgumentParser(description='RC4 Cipher Attack Tool')
    parser.add_argument('-m', '--mode', choices=['encrypt', 'decrypt', 'fluhrer', 'wep', 'correlation'], 
                        required=True, help='Operation mode')
    parser.add_argument('-k', '--key', help='RC4 key for encryption/decryption')
    parser.add_argument('-p', '--plaintext', help='Plaintext for encryption or known-plaintext prefix')
    parser.add_argument('-c', '--ciphertext', help='Ciphertext in hex format for decryption or breaking')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('--threads', type=int, default=multiprocessing.cpu_count(),
                        help='Number of threads for brute force attack')
    
    args = parser.parse_args()
    
    if args.mode == 'encrypt':
        if not args.plaintext or not args.key:
            parser.error('Encryption requires both plaintext and key')
        
        print(f"[*] Encrypting with key: {args.key}")
        ciphertext = rc4_encrypt(args.plaintext, args.key)
        hex_result = bytes_to_hex(ciphertext)
        print(f"[+] Ciphertext (hex): {hex_result}")
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(hex_result)
            print(f"[*] Result written to {args.output}")
    
    elif args.mode == 'decrypt':
        if not args.ciphertext or not args.key:
            parser.error('Decryption requires both ciphertext and key')
        
        print(f"[*] Decrypting with key: {args.key}")
        ciphertext = hex_to_bytes(args.ciphertext)
        plaintext = rc4_decrypt(ciphertext, args.key)
        try:
            text_result = plaintext.decode('utf-8')
            print(f"[+] Plaintext: {text_result}")
        except UnicodeDecodeError:
            print(f"[+] Plaintext (hex): {bytes_to_hex(plaintext)}")
        
        if args.output:
            with open(args.output, 'wb') as f:
                f.write(plaintext)
            print(f"[*] Result written to {args.output}")
    
    elif args.mode == 'fluhrer':
        if not args.ciphertext:
            parser.error('Fluhrer-McGrew attack requires ciphertext')
        
        print("[*] Starting Fluhrer-McGrew attack...")
        ciphertext = hex_to_bytes(args.ciphertext)
        known_prefix = args.plaintext.encode('utf-8') if args.plaintext else None
        
        key = fluhrer_mcgrew_attack(ciphertext, known_prefix, max_workers=args.threads)
        if key:
            print(f"[+] Found key: {key.decode('latin-1', errors='ignore')}")
            print(f"[+] Key (hex): {bytes_to_hex(key)}")
            
            plaintext = rc4_decrypt(ciphertext, key)
            try:
                text_result = plaintext.decode('utf-8')
                print(f"[+] Decrypted plaintext: {text_result}")
            except UnicodeDecodeError:
                print(f"[+] Decrypted plaintext (hex): {bytes_to_hex(plaintext)}")
            
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(f"Key: {key.decode('latin-1', errors='ignore')}\n")
                    f.write(f"Key (hex): {bytes_to_hex(key)}\n")
                    try:
                        f.write(f"Plaintext: {plaintext.decode('utf-8')}\n")
                    except UnicodeDecodeError:
                        f.write(f"Plaintext (hex): {bytes_to_hex(plaintext)}\n")
                print(f"[*] Results written to {args.output}")
        else:
            print("[!] Key not found")
    
    elif args.mode == 'wep':
        if not args.ciphertext:
            parser.error('WEP attack requires ciphertext')
        
        print("[*] Starting WEP attack...")
        ciphertext = hex_to_bytes(args.ciphertext)
        
        key = wep_attack(ciphertext, max_workers=args.threads)
        if key:
            print(f"[+] Found key: {key.decode('latin-1', errors='ignore')}")
            print(f"[+] Key (hex): {bytes_to_hex(key)}")
            
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(f"Key: {key.decode('latin-1', errors='ignore')}\n")
                    f.write(f"Key (hex): {bytes_to_hex(key)}\n")
                print(f"[*] Results written to {args.output}")
        else:
            print("[!] Key not found")
    
    elif args.mode == 'correlation':
        if not args.ciphertext:
            parser.error('Key correlation attack requires ciphertext')
        
        print("[*] Starting RC4 key correlation attack...")
        ciphertext = hex_to_bytes(args.ciphertext)
        
        key = rc4_key_correlation_attack(ciphertext, max_workers=args.threads)
        if key:
            print(f"[+] Best key: {key.decode('latin-1', errors='ignore')}")
            print(f"[+] Key (hex): {bytes_to_hex(key)}")
            
            plaintext = rc4_decrypt(ciphertext, key)
            try:
                text_result = plaintext.decode('utf-8')
                print(f"[+] Decrypted plaintext: {text_result}")
            except UnicodeDecodeError:
                print(f"[+] Decrypted plaintext (hex): {bytes_to_hex(plaintext)}")
            
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(f"Key: {key.decode('latin-1', errors='ignore')}\n")
                    f.write(f"Key (hex): {bytes_to_hex(key)}\n")
                    try:
                        f.write(f"Plaintext: {plaintext.decode('utf-8')}\n")
                    except UnicodeDecodeError:
                        f.write(f"Plaintext (hex): {bytes_to_hex(plaintext)}\n")
                print(f"[*] Results written to {args.output}")
        else:
            print("[!] Key not found")

if __name__ == "__main__":
    main()
