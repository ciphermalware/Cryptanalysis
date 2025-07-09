import argparse
import hashlib
import itertools
import multiprocessing
import os
import random
import string
import time
from collections import defaultdict

def calculate_hash(data, algorithm='md5'):
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    if algorithm == 'md5':
        return hashlib.md5(data).hexdigest()
    elif algorithm == 'sha1':
        return hashlib.sha1(data).hexdigest()
    elif algorithm == 'sha256':
        return hashlib.sha256(data).hexdigest()
    elif algorithm == 'sha512':
        return hashlib.sha512(data).hexdigest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        
def birthday_attack(algorithm='md5', max_attempts=1000000, target_bits=32):
    print(f"[*] Starting birthday attack on {algorithm.upper()}")
    print(f"[*] Looking for collision in first {target_bits} bits")
    
    start_time = time.time()
    seen_hashes = {}
    attempts = 0
    
    while attempts < max_attempts:
        random_data = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        hash_value = calculate_hash(random_data, algorithm)
        
        truncated_hash = hash_value[:target_bits//4]
        
        if truncated_hash in seen_hashes:
            elapsed = time.time() - start_time
            print(f"[+] Collision found after {attempts} attempts in {elapsed:.2f} seconds!")
            print(f"[+] Input 1: {seen_hashes[truncated_hash]}")
            print(f"[+] Input 2: {random_data}")
            print(f"[+] Hash 1: {calculate_hash(seen_hashes[truncated_hash], algorithm)}")
            print(f"[+] Hash 2: {calculate_hash(random_data, algorithm)}")
            print(f"[+] Colliding prefix: {truncated_hash}")
            return seen_hashes[truncated_hash], random_data
        
        seen_hashes[truncated_hash] = random_data
        attempts += 1
        
        if attempts % 10000 == 0:
            print(f"[*] Tried {attempts} hashes...")
    
    elapsed = time.time() - start_time
    print(f"[!] No collision found after {max_attempts} attempts in {elapsed:.2f} seconds")
    return None

def brute_force_collision(target_hash, algorithm='md5', charset=None, max_length=8, max_workers=None):
    print(f"[*] Starting brute force attack to find collision with hash: {target_hash}")
    start_time = time.time()
    
    if charset is None:
        charset = string.ascii_lowercase + string.digits
    
    def check_batch(length_and_batch):
        length, batch = length_and_batch
        for candidate in batch:
            candidate_str = ''.join(candidate)
            if calculate_hash(candidate_str, algorithm) == target_hash:
                return candidate_str
        return None
    
    for length in range(1, max_length + 1):
        print(f"[*] Trying length {length}...")
        
        batch_size = 10000
        batches = []
        current_batch = []
        
        for candidate in itertools.product(charset, repeat=length):
            current_batch.append(candidate)
            
            if len(current_batch) >= batch_size:
                batches.append((length, current_batch))
                current_batch = []
                
                if len(batches) >= 100:
                    break
        
        if current_batch:
            batches.append((length, current_batch))
        
        with multiprocessing.Pool(processes=max_workers) as pool:
            for result in pool.imap_unordered(check_batch, batches):
                if result is not None:
                    pool.terminate()
                    elapsed = time.time() - start_time
                    print(f"[+] Collision found! Time elapsed: {elapsed:.2f} seconds")
                    print(f"[+] Input: {result}")
                    print(f"[+] Hash: {calculate_hash(result, algorithm)}")
                    return result
    
    elapsed = time.time() - start_time
    print(f"[!] No collision found after {elapsed:.2f} seconds")
    return None

def generate_rainbow_table(algorithm='md5', charset=None, max_length=6, table_size=100000):
    print(f"[*] Generating rainbow table for {algorithm.upper()}")
    print(f"[*] Target size: {table_size} entries")
    
    if charset is None:
        charset = string.ascii_lowercase + string.digits
    
    start_time = time.time()
    rainbow_table = {}
    
    generated = 0
    for length in range(1, max_length + 1):
        for candidate in itertools.product(charset, repeat=length):
            if generated >= table_size:
                break
                
            candidate_str = ''.join(candidate)
            hash_value = calculate_hash(candidate_str, algorithm)
            rainbow_table[hash_value] = candidate_str
            
            generated += 1
            
            if generated % 10000 == 0:
                print(f"[*] Generated {generated} entries...")
        
        if generated >= table_size:
            break
    
    elapsed = time.time() - start_time
    print(f"[+] Rainbow table generated with {len(rainbow_table)} entries in {elapsed:.2f} seconds")
    
    return rainbow_table

def rainbow_table_lookup(hash_value, rainbow_table):
    print(f"[*] Looking up hash: {hash_value}")
    
    if hash_value in rainbow_table:
        result = rainbow_table[hash_value]
        print(f"[+] Found in rainbow table!")
        print(f"[+] Input: {result}")
        return result
    else:
        print(f"[!] Hash not found in rainbow table")
        return None

def known_md5_collisions():
    print("[*] Demonstrating known MD5 collisions")
    
    collision1_hex = "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70"
    collision2_hex = "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70"
    
    collision1 = bytes.fromhex(collision1_hex)
    collision2 = bytes.fromhex(collision2_hex)
    
    hash1 = hashlib.md5(collision1).hexdigest()
    hash2 = hashlib.md5(collision2).hexdigest()
    
    print(f"[+] Collision 1 hash: {hash1}")
    print(f"[+] Collision 2 hash: {hash2}")
    print(f"[+] Hashes match: {hash1 == hash2}")
    print(f"[+] Data different: {collision1 != collision2}")
    
    return collision1_hex, collision2_hex

def length_extension_attack(original_hash, original_length, append_data, algorithm='md5'):
    print(f"[*] Simulating length extension attack on {algorithm.upper()}")
    print(f"[*] Original hash: {original_hash}")
    print(f"[*] Original length: {original_length}")
    print(f"[*] Data to append: {append_data}")
    
    if algorithm not in ['md5', 'sha1']:
        print(f"[!] Length extension attack not applicable to {algorithm}")
        return None
    
    block_size = 64 if algorithm in ['md5', 'sha1'] else 128
    
    padding_length = block_size - ((original_length + 9) % block_size)
    if padding_length == block_size:
        padding_length = 0
    
    total_length = original_length + 1 + padding_length + 8
    new_length = total_length + len(append_data)
    
    print(f"[*] Calculated padding length: {padding_length}")
    print(f"[*] New total length: {new_length}")
    
    simulated_extended_hash = hashlib.md5(f"extended_hash_simulation_{original_hash}_{append_data}".encode()).hexdigest()
    
    print(f"[+] Simulated extended hash: {simulated_extended_hash}")
    print(f"[+] In a real attack, this would be the hash of: original_data + padding + {append_data}")
    
    return simulated_extended_hash

def hash_performance_analysis(data_sizes, algorithms, iterations=1000):
    print("[*] Analyzing hash function performance")
    
    results = {}
    
    for algorithm in algorithms:
        results[algorithm] = {}
        print(f"[*] Testing {algorithm.upper()}...")
        
        for size in data_sizes:
            test_data = os.urandom(size)
            
            start_time = time.time()
            for _ in range(iterations):
                calculate_hash(test_data, algorithm)
            elapsed = time.time() - start_time
            
            rate = (size * iterations) / elapsed / 1024 / 1024
            results[algorithm][size] = {
                'time': elapsed,
                'rate_mbps': rate
            }
            
            print(f"[+] {size} bytes: {rate:.2f} MB/s")
    
    return results

def collision_probability_calculator(hash_bits, num_hashes):
    print(f"[*] Calculating collision probability for {hash_bits}-bit hash with {num_hashes} hashes")
    
    if num_hashes > 2**hash_bits:
        probability = 1.0
    else:
        probability = 1.0
        for i in range(num_hashes):
            probability *= (2**hash_bits - i) / (2**hash_bits)
        probability = 1.0 - probability
    
    print(f"[+] Collision probability: {probability:.6f} ({probability*100:.4f}%)")
    
    birthday_bound = int((2**hash_bits * 0.5) ** 0.5)
    print(f"[+] 50% collision probability at: ~{birthday_bound} hashes")
    
    return probability

def main():
    parser = argparse.ArgumentParser(description='Hash Collision Attack Tool')
    parser.add_argument('-m', '--mode', choices=['hash', 'birthday', 'brute', 'rainbow-gen', 'rainbow-lookup', 'known-md5', 'length-ext', 'performance', 'probability'], 
                        required=True, help='Operation mode')
    parser.add_argument('-a', '--algorithm', choices=['md5', 'sha1', 'sha256', 'sha512'], 
                        default='md5', help='Hash algorithm')
    parser.add_argument('-d', '--data', help='Data to hash or target hash for attacks')
    parser.add_argument('-f', '--file', help='File to hash')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('--max-attempts', type=int, default=1000000, help='Maximum attempts for birthday attack')
    parser.add_argument('--target-bits', type=int, default=32, help='Target bits for collision')
    parser.add_argument('--max-length', type=int, default=8, help='Maximum length for brute force')
    parser.add_argument('--table-size', type=int, default=100000, help='Rainbow table size')
    parser.add_argument('--threads', type=int, default=multiprocessing.cpu_count(), help='Number of threads')
    
    args = parser.parse_args()
    
    if args.mode == 'hash':
        if args.file:
            with open(args.file, 'rb') as f:
                data = f.read()
        elif args.data:
            data = args.data
        else:
            parser.error('Hash mode requires either --data or --file')
        
        hash_value = calculate_hash(data, args.algorithm)
        print(f"[+] {args.algorithm.upper()} hash: {hash_value}")
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(hash_value)
            print(f"[*] Hash written to {args.output}")
    
    elif args.mode == 'birthday':
        result = birthday_attack(args.algorithm, args.max_attempts, args.target_bits)
        
        if result and args.output:
            input1, input2 = result
            with open(args.output, 'w') as f:
                f.write(f"Input 1: {input1}\n")
                f.write(f"Input 2: {input2}\n")
                f.write(f"Hash 1: {calculate_hash(input1, args.algorithm)}\n")
                f.write(f"Hash 2: {calculate_hash(input2, args.algorithm)}\n")
            print(f"[*] Results written to {args.output}")
    
    elif args.mode == 'brute':
        if not args.data:
            parser.error('Brute force mode requires --data (target hash)')
        
        result = brute_force_collision(args.data, args.algorithm, max_length=args.max_length, max_workers=args.threads)
        
        if result and args.output:
            with open(args.output, 'w') as f:
                f.write(f"Input: {result}\n")
                f.write(f"Hash: {calculate_hash(result, args.algorithm)}\n")
            print(f"[*] Results written to {args.output}")
    
    elif args.mode == 'rainbow-gen':
        rainbow_table = generate_rainbow_table(args.algorithm, table_size=args.table_size, max_length=args.max_length)
        
        if args.output:
            with open(args.output, 'w') as f:
                for hash_val, input_val in rainbow_table.items():
                    f.write(f"{hash_val}:{input_val}\n")
            print(f"[*] Rainbow table written to {args.output}")
    
    elif args.mode == 'rainbow-lookup':
        if not args.data:
            parser.error('Rainbow lookup mode requires --data (hash to lookup)')
        if not args.file:
            parser.error('Rainbow lookup mode requires --file (rainbow table file)')
        
        rainbow_table = {}
        with open(args.file, 'r') as f:
            for line in f:
                hash_val, input_val = line.strip().split(':', 1)
                rainbow_table[hash_val] = input_val
        
        result = rainbow_table_lookup(args.data, rainbow_table)
        
        if result and args.output:
            with open(args.output, 'w') as f:
                f.write(f"Hash: {args.data}\n")
                f.write(f"Input: {result}\n")
            print(f"[*] Results written to {args.output}")
    
    elif args.mode == 'known-md5':
        collision1, collision2 = known_md5_collisions()
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(f"Collision 1 (hex): {collision1}\n")
                f.write(f"Collision 2 (hex): {collision2}\n")
            print(f"[*] Results written to {args.output}")
    
    elif args.mode == 'length-ext':
        if not args.data:
            parser.error('Length extension mode requires --data in format "hash:length:append_data"')
        
        try:
            hash_val, length_str, append_data = args.data.split(':', 2)
            length = int(length_str)
        except ValueError:
            parser.error('Data format should be "hash:length:append_data"')
        
        result = length_extension_attack(hash_val, length, append_data, args.algorithm)
        
        if result and args.output:
            with open(args.output, 'w') as f:
                f.write(f"Original hash: {hash_val}\n")
                f.write(f"Extended hash: {result}\n")
                f.write(f"Appended data: {append_data}\n")
            print(f"[*] Results written to {args.output}")
    
    elif args.mode == 'performance':
        data_sizes = [1024, 4096, 16384, 65536, 262144]
        algorithms = ['md5', 'sha1', 'sha256', 'sha512']
        
        results = hash_performance_analysis(data_sizes, algorithms)
        
        if args.output:
            with open(args.output, 'w') as f:
                for algorithm, size_results in results.items():
                    f.write(f"\n{algorithm.upper()}:\n")
                    for size, metrics in size_results.items():
                        f.write(f"  {size} bytes: {metrics['rate_mbps']:.2f} MB/s\n")
            print(f"[*] Results written to {args.output}")
    
    elif args.mode == 'probability':
        if not args.data:
            parser.error('Probability mode requires --data in format "hash_bits:num_hashes"')
        
        try:
            hash_bits_str, num_hashes_str = args.data.split(':', 1)
            hash_bits = int(hash_bits_str)
            num_hashes = int(num_hashes_str)
        except ValueError:
            parser.error('Data format should be "hash_bits:num_hashes"')
        
        probability = collision_probability_calculator(hash_bits, num_hashes)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(f"Hash bits: {hash_bits}\n")
                f.write(f"Number of hashes: {num_hashes}\n")
                f.write(f"Collision probability: {probability:.6f}\n")
            print(f"[*] Results written to {args.output}")

if __name__ == "__main__":
    main()
