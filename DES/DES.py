import time
import binascii
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import multiprocessing
import itertools
import os
import argparse

def des_encrypt(plaintext, key, mode=DES.MODE_ECB):
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')
        
    cipher = DES.new(key, mode)
    padded_plaintext = pad(plaintext, DES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

def des_decrypt(ciphertext, key, mode=DES.MODE_ECB):
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    cipher = DES.new(key, mode)
    padded_plaintext = cipher.decrypt(ciphertext)
    try:
        plaintext = unpad(padded_plaintext, DES.block_size)
        return plaintext
    except ValueError:
        return padded_plaintext

def bytes_to_hex(data):
    return binascii.hexlify(data).decode('ascii')

def hex_to_bytes(hex_str):
    return binascii.unhexlify(hex_str)

def brute_force_des(ciphertext, known_plaintext=None, key_pattern=None, max_workers=None):
    print("[*] Starting brute force attack...")
    start_time = time.time()
    
    has_known_plaintext = known_plaintext is not None
    if has_known_plaintext and isinstance(known_plaintext, str):
        known_plaintext = known_plaintext.encode('utf-8')
    
    if key_pattern is None:
        print("[!] No key pattern provided. Using a limited character set for demonstration.")
        charset = ''.join(chr(i) for i in range(48, 123))
        key_length = 8
        
        print(f"[*] Using charset: {charset}")
        print(f"[*] Testing keys with fixed pattern and variable positions")
        
        fixed_prefix = "DES12345"[:5]
        variable_length = key_length - len(fixed_prefix)
        
        print(f"[*] Fixed prefix: {fixed_prefix}, Testing {len(charset)**variable_length} combinations")
        
        def key_generator():
            for suffix in itertools.product(charset, repeat=variable_length):
                yield (fixed_prefix + ''.join(suffix)).encode('utf-8')
    else:
        key_generator = key_pattern
    
    def check_key_batch(keys_batch):
        for key in keys_batch:
            try:
                plaintext = des_decrypt(ciphertext, key)
                
                if has_known_plaintext:
                    if plaintext == known_plaintext:
                        return key
                else:
                    printable_ratio = sum(32 <= b <= 126 for b in plaintext) / len(plaintext)
                    if printable_ratio > 0.8:
                        return key
            except Exception:
                continue
        return None
    
    batch_size = 10000
    keys_batches = []
    current_batch = []
    
    for i, key in enumerate(key_generator()):
        current_batch.append(key)
        if len(current_batch) >= batch_size:
            keys_batches.append(current_batch)
            current_batch = []
            
            if i % (batch_size * 10) == 0:
                elapsed = time.time() - start_time
                print(f"[*] Tested {i} keys in {elapsed:.2f} seconds ({i/elapsed:.2f} keys/sec)")
                
        if len(keys_batches) >= 100:
            if current_batch:
                keys_batches.append(current_batch)
            break
    
    if current_batch:
        keys_batches.append(current_batch)
    
    print(f"[*] Testing {sum(len(batch) for batch in keys_batches)} keys in {len(keys_batches)} batches")
    
    with multiprocessing.Pool(processes=max_workers) as pool:
        for result in pool.imap_unordered(check_key_batch, keys_batches):
            if result is not None:
                pool.terminate()
                elapsed = time.time() - start_time
                print(f"[+] Key found! Time elapsed: {elapsed:.2f} seconds")
                return result
    
    elapsed = time.time() - start_time
    print(f"[!] Key not found after {elapsed:.2f} seconds")
    return None

def known_plaintext_attack(plaintext, ciphertext, key_space=None):
    print("[*] Starting known-plaintext attack...")
    return brute_force_des(ciphertext, known_plaintext=plaintext, key_pattern=key_space)

def meet_in_the_middle_attack(plaintext, ciphertext, key_space1=None, key_space2=None):
    print("[*] Starting meet-in-the-middle attack...")
    start_time = time.time()
    
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    if key_space1 is None or key_space2 is None:
        print("[!] Using extremely limited key space for demonstration")
        charset = ''.join(chr(i) for i in range(32, 127))
        
        fixed_suffix = "DES!2023"[4:]
        variable_length = 4
        
        def key_generator():
            for prefix in itertools.product(charset, repeat=variable_length):
                yield (''.join(prefix) + fixed_suffix).encode('utf-8')
                
        key_space1 = key_generator
        key_space2 = key_generator
    
    lookup_table = {}
    
    padded_plaintext = pad(plaintext, DES.block_size)
    
    count = 0
    print("[*] Building lookup table...")
    for key1 in key_space1():
        cipher1 = DES.new(key1, DES.MODE_ECB)
        intermediate = cipher1.encrypt(padded_plaintext)
        lookup_table[intermediate] = key1
        
        count += 1
        if count % 10000 == 0:
            print(f"[*] Added {count} entries to lookup table")
        
        if count >= 100000:
            break
    
    print(f"[*] Lookup table complete with {len(lookup_table)} entries")
    
    count = 0
    print("[*] Testing second-stage keys...")
    for key2 in key_space2():
        cipher2 = DES.new(key2, DES.MODE_ECB)
        intermediate_candidate = cipher2.decrypt(ciphertext)
        
        if intermediate_candidate in lookup_table:
            key1 = lookup_table[intermediate_candidate]
            elapsed = time.time() - start_time
            print(f"[+] Keys found! Time elapsed: {elapsed:.2f} seconds")
            return (key1, key2)
        
        count += 1
        if count % 10000 == 0:
            print(f"[*] Tested {count} second-stage keys")
            
        if count >= 100000:
            break
    
    elapsed = time.time() - start_time
    print(f"[!] Keys not found after {elapsed:.2f} seconds")
    return None

DES_WEAK_KEYS = [
    b'\x01\x01\x01\x01\x01\x01\x01\x01',
    b'\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE',
    b'\x1F\x1F\x1F\x1F\x0E\x0E\x0E\x0E',
    b'\xE0\xE0\xE0\xE0\xF1\xF1\xF1\xF1'
]

def check_weak_keys(key):
    if isinstance(key, str):
        key = key.encode('utf-8')
    return key in DES_WEAK_KEYS

def main():
    parser = argparse.ArgumentParser(description='DES Cipher Attack Tool')
    parser.add_argument('-m', '--mode', choices=['encrypt', 'decrypt', 'brute', 'known', 'mitm'], 
                        required=True, help='Operation mode')
    parser.add_argument('-k', '--key', help='Encryption/decryption key')
    parser.add_argument('-p', '--plaintext', help='Plaintext for encryption or known-plaintext attack')
    parser.add_argument('-c', '--ciphertext', help='Ciphertext in hex format for decryption or breaking')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('--threads', type=int, default=multiprocessing.cpu_count(),
                        help='Number of threads for brute force attack')
    
    args = parser.parse_args()
    
    if args.mode == 'encrypt':
        if not args.plaintext or not args.key:
            parser.error('Encryption requires both plaintext and key')
        
        print(f"[*] Encrypting with key: {args.key}")
        ciphertext = des_encrypt(args.plaintext, args.key)
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
        plaintext = des_decrypt(ciphertext, args.key)
        try:
            text_result = plaintext.decode('utf-8')
            print(f"[+] Plaintext: {text_result}")
        except UnicodeDecodeError:
            print(f"[+] Plaintext (hex): {bytes_to_hex(plaintext)}")
        
        if args.output:
            with open(args.output, 'wb') as f:
                f.write(plaintext)
            print(f"[*] Result written to {args.output}")
    
    elif args.mode == 'brute':
        if not args.ciphertext:
            parser.error('Brute force attack requires ciphertext')
        
        print("[*] Starting brute force attack...")
        ciphertext = hex_to_bytes(args.ciphertext)
        known_plaintext = args.plaintext.encode('utf-8') if args.plaintext else None
        
        key = brute_force_des(ciphertext, known_plaintext, max_workers=args.threads)
        if key:
            print(f"[+] Found key: {key.decode('latin-1')}")
            print(f"[+] Key (hex): {bytes_to_hex(key)}")
            
            plaintext = des_decrypt(ciphertext, key)
            try:
                text_result = plaintext.decode('utf-8')
                print(f"[+] Decrypted plaintext: {text_result}")
            except UnicodeDecodeError:
                print(f"[+] Decrypted plaintext (hex): {bytes_to_hex(plaintext)}")
            
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(f"Key: {key.decode('latin-1')}\n")
                    f.write(f"Key (hex): {bytes_to_hex(key)}\n")
                    try:
                        f.write(f"Plaintext: {plaintext.decode('utf-8')}\n")
                    except UnicodeDecodeError:
                        f.write(f"Plaintext (hex): {bytes_to_hex(plaintext)}\n")
                print(f"[*] Results written to {args.output}")
        else:
            print("[!] Key not found")
    
    elif args.mode == 'known':
        if not args.ciphertext or not args.plaintext:
            parser.error('Known-plaintext attack requires both plaintext and ciphertext')
        
        print("[*] Starting known-plaintext attack...")
        ciphertext = hex_to_bytes(args.ciphertext)
        
        key = known_plaintext_attack(args.plaintext, ciphertext)
        if key:
            print(f"[+] Found key: {key.decode('latin-1')}")
            print(f"[+] Key (hex): {bytes_to_hex(key)}")
            
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(f"Key: {key.decode('latin-1')}\n")
                    f.write(f"Key (hex): {bytes_to_hex(key)}\n")
                print(f"[*] Results written to {args.output}")
        else:
            print("[!] Key not found")
    
    elif args.mode == 'mitm':
        if not args.ciphertext or not args.plaintext:
            parser.error('Meet-in-the-middle attack requires both plaintext and ciphertext')
        
        print("[*] Starting meet-in-the-middle attack (demonstration)...")
        ciphertext = hex_to_bytes(args.ciphertext)
        
        keys = meet_in_the_middle_attack(args.plaintext, ciphertext)
        if keys:
            key1, key2 = keys
            print(f"[+] Found keys:")
            print(f"    Key1: {key1.decode('latin-1')}")
            print(f"    Key1 (hex): {bytes_to_hex(key1)}")
            print(f"    Key2: {key2.decode('latin-1')}")
            print(f"    Key2 (hex): {bytes_to_hex(key2)}")
            
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(f"Key1: {key1.decode('latin-1')}\n")
                    f.write(f"Key1 (hex): {bytes_to_hex(key1)}\n")
                    f.write(f"Key2: {key2.decode('latin-1')}\n")
                    f.write(f"Key2 (hex): {bytes_to_hex(key2)}\n")
                print(f"[*] Results written to {args.output}")
        else:
            print("[!] Keys not found")

if __name__ == "__main__":
    main()
