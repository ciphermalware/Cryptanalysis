import argparse
import random
import math
import time
import hashlib
from collections import defaultdict

def mod_exp(base, exponent, modulus):
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y

def mod_inverse(a, m):
    gcd_val, x, y = extended_gcd(a, m)
    if gcd_val != 1:
        return None
    return (x % m + m) % m

def is_prime(n, k=10):
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = mod_exp(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = mod_exp(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_safe_prime(bits):
    while True:
        q = random.getrandbits(bits - 1)
        q |= (1 << (bits - 2)) | 1
        if is_prime(q):
            p = 2 * q + 1
            if is_prime(p):
                return p, q

def find_generator(p, q=None):
    if q is None:
        q = (p - 1) // 2
    
    for g in range(2, min(p, 1000)):
        if mod_exp(g, 2, p) != 1 and mod_exp(g, q, p) != 1:
            return g
    return None

def baby_step_giant_step(g, h, p, max_steps=None):
    print(f"[*] Starting Baby-step Giant-step attack")
    print(f"[*] Finding x such that g^x ≡ h (mod p)")
    print(f"[*] g = {g}, h = {h}, p = {p}")
    
    if max_steps is None:
        max_steps = int(math.sqrt(p)) + 1
    
    start_time = time.time()
    
    m = int(math.sqrt(max_steps)) + 1
    
    baby_steps = {}
    gamma = 1
    for j in range(m):
        if gamma == h:
            elapsed = time.time() - start_time
            print(f"[+] Found solution: x = {j} in {elapsed:.3f} seconds")
            return j
        baby_steps[gamma] = j
        gamma = (gamma * g) % p
    
    factor = mod_exp(g, m, p)
    factor_inv = mod_inverse(factor, p)
    if factor_inv is None:
        print(f"[!] Cannot compute modular inverse")
        return None
    
    y = h
    for i in range(m):
        if y in baby_steps:
            x = i * m + baby_steps[y]
            if mod_exp(g, x, p) == h:
                elapsed = time.time() - start_time
                print(f"[+] Found solution: x = {x} in {elapsed:.3f} seconds")
                return x
        y = (y * factor_inv) % p
    
    elapsed = time.time() - start_time
    print(f"[!] No solution found in {elapsed:.3f} seconds")
    return None

def pollard_rho(g, h, p, q=None):
    print(f"[*] Starting Pollard's rho attack")
    print(f"[*] Finding x such that g^x ≡ h (mod p)")
    
    if q is None:
        q = p - 1
    
    start_time = time.time()
    
    def f(x, a, b):
        if x % 3 == 0:
            return (x * x) % p, (2 * a) % q, (2 * b) % q
        elif x % 3 == 1:
            return (x * g) % p, (a + 1) % q, b
        else:
            return (x * h) % p, a, (b + 1) % q
    
    x1, a1, b1 = 1, 0, 0
    x2, a2, b2 = 1, 0, 0
    
    for i in range(1, int(math.sqrt(q)) + 1):
        x1, a1, b1 = f(x1, a1, b1)
        x2, a2, b2 = f(*f(x2, a2, b2))
        
        if x1 == x2:
            r = (a1 - a2) % q
            s = (b2 - b1) % q
            
            if s == 0:
                print(f"[!] Failure: s = 0, trying again...")
                continue
            
            s_inv = mod_inverse(s, q)
            if s_inv is None:
                print(f"[!] Cannot compute modular inverse of s")
                continue
            
            x = (r * s_inv) % q
            
            if mod_exp(g, x, p) == h:
                elapsed = time.time() - start_time
                print(f"[+] Found solution: x = {x} in {elapsed:.3f} seconds")
                return x
    
    elapsed = time.time() - start_time
    print(f"[!] Pollard's rho failed in {elapsed:.3f} seconds")
    return None

def pohlig_hellman(g, h, p, factors=None):
    print(f"[*] Starting Pohlig-Hellman attack")
    
    if factors is None:
        n = p - 1
        factors = factorize_simple(n)
    
    print(f"[*] Using factors: {factors}")
    
    if not factors:
        print(f"[!] No small factors found")
        return None
    
    start_time = time.time()
    remainders = []
    moduli = []
    
    for prime, power in factors:
        if prime > 1000000:
            print(f"[!] Factor {prime} too large, skipping")
            continue
            
        mod = prime ** power
        g_reduced = mod_exp(g, (p - 1) // mod, p)
        h_reduced = mod_exp(h, (p - 1) // mod, p)
        
        x_i = baby_step_giant_step(g_reduced, h_reduced, p, mod)
        if x_i is not None:
            remainders.append(x_i)
            moduli.append(mod)
            print(f"[+] Found x ≡ {x_i} (mod {mod})")
    
    if not remainders:
        print(f"[!] No partial solutions found")
        return None
    
    x = chinese_remainder_theorem(remainders, moduli)
    if x is not None and mod_exp(g, x, p) == h:
        elapsed = time.time() - start_time
        print(f"[+] Found solution: x = {x} in {elapsed:.3f} seconds")
        return x
    
    elapsed = time.time() - start_time
    print(f"[!] Pohlig-Hellman failed in {elapsed:.3f} seconds")
    return None

def chinese_remainder_theorem(remainders, moduli):
    if len(remainders) != len(moduli):
        return None
    
    total = 0
    prod = 1
    for m in moduli:
        prod *= m
    
    for r, m in zip(remainders, moduli):
        p = prod // m
        total += r * mod_inverse(p, m) * p
    
    return total % prod

def factorize_simple(n, max_factor=10000):
    factors = []
    d = 2
    while d * d <= n and d <= max_factor:
        power = 0
        while n % d == 0:
            n //= d
            power += 1
        if power > 0:
            factors.append((d, power))
        d += 1
    if n > 1 and n <= max_factor:
        factors.append((n, 1))
    return factors

def diffie_hellman_exchange(p, g, private_a=None, private_b=None):
    print(f"[*] Performing Diffie-Hellman key exchange")
    print(f"[*] Public parameters: p = {p}, g = {g}")
    
    if private_a is None:
        private_a = random.randint(1, p - 2)
    if private_b is None:
        private_b = random.randint(1, p - 2)
    
    public_a = mod_exp(g, private_a, p)
    public_b = mod_exp(g, private_b, p)
    
    shared_secret_a = mod_exp(public_b, private_a, p)
    shared_secret_b = mod_exp(public_a, private_b, p)
    
    print(f"[+] Alice: private = {private_a}, public = {public_a}")
    print(f"[+] Bob: private = {private_b}, public = {public_b}")
    print(f"[+] Shared secret: {shared_secret_a}")
    
    assert shared_secret_a == shared_secret_b
    
    return {
        'p': p,
        'g': g,
        'private_a': private_a,
        'private_b': private_b,
        'public_a': public_a,
        'public_b': public_b,
        'shared_secret': shared_secret_a
    }

def small_subgroup_attack(p, g, public_key, subgroup_orders=None):
    print(f"[*] Starting small subgroup attack")
    print(f"[*] Target public key: {public_key}")
    
    if subgroup_orders is None:
        subgroup_orders = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
    
    start_time = time.time()
    partial_info = []
    
    for order in subgroup_orders:
        if (p - 1) % order != 0:
            continue
        
        subgroup_generator = mod_exp(g, (p - 1) // order, p)
        if subgroup_generator == 1:
            continue
        
        reduced_public = mod_exp(public_key, (p - 1) // order, p)
        
        for x in range(order):
            if mod_exp(subgroup_generator, x, p) == reduced_public:
                partial_info.append((x, order))
                print(f"[+] Found: private_key ≡ {x} (mod {order})")
                break
    
    if partial_info:
        remainders = [x for x, _ in partial_info]
        moduli = [order for _, order in partial_info]
        
        recovered_key = chinese_remainder_theorem(remainders, moduli)
        if recovered_key is not None:
            elapsed = time.time() - start_time
            print(f"[+] Partial key recovery: {recovered_key} (mod {math.prod(moduli)})")
            print(f"[*] Attack completed in {elapsed:.3f} seconds")
            return recovered_key, math.prod(moduli)
    
    elapsed = time.time() - start_time
    print(f"[!] Small subgroup attack failed in {elapsed:.3f} seconds")
    return None, None

def invalid_curve_attack_sim():
    print(f"[*] Simulating invalid curve attack on ECDH")
    print(f"[*] This demonstrates how an attacker can send points on weak curves")
    
    print(f"[+] Original curve: y² = x³ + ax + b (mod p)")
    print(f"[+] Invalid curve: y² = x³ + a'x + b' (mod p)")
    print(f"[+] Invalid curve has small order, allowing discrete log computation")
    print(f"[+] Attacker recovers bits of private key through multiple invalid curves")
    
    return "Invalid curve attack simulation completed"

def weak_parameter_analysis(p, g):
    print(f"[*] Analyzing Diffie-Hellman parameters for weaknesses")
    print(f"[*] p = {p}")
    print(f"[*] g = {g}")
    
    issues = []
    
    if p.bit_length() < 1024:
        issues.append(f"Prime p is only {p.bit_length()} bits (should be ≥1024)")
    
    if not is_prime(p):
        issues.append("p is not prime")
    
    if p in [2, 5, 23, 47]:
        issues.append("p is a known weak prime")
    
    if g <= 1 or g >= p:
        issues.append("Generator g is out of valid range")
    
    if mod_exp(g, 2, p) == 1:
        issues.append("Generator g has order 2 (very weak)")
    
    if gcd(g, p) != 1:
        issues.append("Generator g and p are not coprime")
    
    order_checks = [2, 3, 5, 7, 11, 13, 17, 19, 23]
    small_orders = []
    for order in order_checks:
        if mod_exp(g, order, p) == 1:
            small_orders.append(order)
    
    if small_orders:
        issues.append(f"Generator has small order factors: {small_orders}")
    
    factors = factorize_simple(p - 1, 100000)
    smooth_factors = [f for f, _ in factors if f < 1000]
    if len(smooth_factors) > len(factors) // 2:
        issues.append(f"p-1 has many small factors: {smooth_factors}")
    
    if issues:
        print(f"[!] Security issues found:")
        for issue in issues:
            print(f"    - {issue}")
        return False, issues
    else:
        print(f"[+] Parameters appear secure")
        return True, []

def logjam_attack_sim(p, g, public_key):
    print(f"[*] Simulating Logjam attack")
    print(f"[*] This attack targets 512-bit primes used in real protocols")
    
    if p.bit_length() <= 512:
        print(f"[+] Prime size ({p.bit_length()} bits) vulnerable to Logjam")
        print(f"[+] Precomputation phase would take significant resources")
        print(f"[+] Individual discrete logs become feasible after precomputation")
        
        if p.bit_length() <= 64:
            print(f"[*] Attempting actual discrete log (small prime)")
            result = baby_step_giant_step(g, public_key, p)
            if result:
                return result
        
        return "Logjam attack would be successful"
    else:
        print(f"[!] Prime size ({p.bit_length()} bits) likely secure against Logjam")
        return None

def man_in_the_middle_sim():
    print(f"[*] Simulating Man-in-the-Middle attack on Diffie-Hellman")
    
    p = 23
    g = 5
    
    alice_private = 6
    bob_private = 15
    eve_private_a = 3
    eve_private_b = 12
    
    alice_public = mod_exp(g, alice_private, p)
    bob_public = mod_exp(g, bob_private, p)
    
    eve_public_to_alice = mod_exp(g, eve_private_a, p)
    eve_public_to_bob = mod_exp(g, eve_private_b, p)
    
    alice_shared = mod_exp(eve_public_to_alice, alice_private, p)
    bob_shared = mod_exp(eve_public_to_bob, bob_private, p)
    
    eve_shared_with_alice = mod_exp(alice_public, eve_private_a, p)
    eve_shared_with_bob = mod_exp(bob_public, eve_private_b, p)
    
    print(f"[+] Alice thinks shared secret is: {alice_shared}")
    print(f"[+] Bob thinks shared secret is: {bob_shared}")
    print(f"[+] Eve can decrypt Alice's messages using: {eve_shared_with_alice}")
    print(f"[+] Eve can decrypt Bob's messages using: {eve_shared_with_bob}")
    print(f"[+] Alice and Bob have different secrets - MITM successful!")
    
    return {
        'alice_shared': alice_shared,
        'bob_shared': bob_shared,
        'eve_alice_shared': eve_shared_with_alice,
        'eve_bob_shared': eve_shared_with_bob
    }

def main():
    parser = argparse.ArgumentParser(description='Diffie-Hellman Attack Tool')
    parser.add_argument('-m', '--mode', 
                        choices=['keygen', 'exchange', 'baby-giant', 'pollard', 'pohlig', 'subgroup', 'invalid-curve', 'weak-params', 'logjam', 'mitm'], 
                        required=True, help='Operation mode')
    parser.add_argument('-p', '--prime', type=int, help='Prime modulus p')
    parser.add_argument('-g', '--generator', type=int, help='Generator g')
    parser.add_argument('-k', '--public-key', type=int, help='Public key for attacks')
    parser.add_argument('-b', '--bits', type=int, default=512, help='Bit length for key generation')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('--private-a', type=int, help='Alice private key')
    parser.add_argument('--private-b', type=int, help='Bob private key')
    
    args = parser.parse_args()
    
    if args.mode == 'keygen':
        print(f"[*] Generating {args.bits}-bit Diffie-Hellman parameters")
        start_time = time.time()
        
        if args.bits <= 64:
            p, q = generate_safe_prime(args.bits)
            g = find_generator(p, q)
        else:
            print(f"[!] Large prime generation not implemented for {args.bits} bits")
            print(f"[*] Using well-known test parameters")
            if args.bits <= 512:
                p = 2**127 - 1
                g = 2
            else:
                p = 2**255 - 19
                g = 2
        
        elapsed = time.time() - start_time
        print(f"[+] Generated parameters in {elapsed:.3f} seconds")
        print(f"[+] Prime p = {p}")
        print(f"[+] Generator g = {g}")
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(f"p = {p}\n")
                f.write(f"g = {g}\n")
            print(f"[*] Parameters written to {args.output}")
    
    elif args.mode == 'exchange':
        if not args.prime or not args.generator:
            parser.error('Exchange mode requires --prime and --generator')
        
        result = diffie_hellman_exchange(args.prime, args.generator, args.private_a, args.private_b)
        
        if args.output:
            with open(args.output, 'w') as f:
                for key, value in result.items():
                    f.write(f"{key} = {value}\n")
            print(f"[*] Exchange results written to {args.output}")
    
    elif args.mode == 'baby-giant':
        if not args.prime or not args.generator or not args.public_key:
            parser.error('Baby-giant mode requires --prime, --generator, and --public-key')
        
        result = baby_step_giant_step(args.generator, args.public_key, args.prime)
        
        if result and args.output:
            with open(args.output, 'w') as f:
                f.write(f"private_key = {result}\n")
                f.write(f"verification: {args.generator}^{result} mod {args.prime} = {mod_exp(args.generator, result, args.prime)}\n")
            print(f"[*] Results written to {args.output}")
    
    elif args.mode == 'pollard':
        if not args.prime or not args.generator or not args.public_key:
            parser.error('Pollard mode requires --prime, --generator, and --public-key')
        
        result = pollard_rho(args.generator, args.public_key, args.prime)
        
        if result and args.output:
            with open(args.output, 'w') as f:
                f.write(f"private_key = {result}\n")
            print(f"[*] Results written to {args.output}")
    
    elif args.mode == 'pohlig':
        if not args.prime or not args.generator or not args.public_key:
            parser.error('Pohlig mode requires --prime, --generator, and --public-key')
        
        factors = factorize_simple(args.prime - 1)
        result = pohlig_hellman(args.generator, args.public_key, args.prime, factors)
        
        if result and args.output:
            with open(args.output, 'w') as f:
                f.write(f"private_key = {result}\n")
            print(f"[*] Results written to {args.output}")
    
    elif args.mode == 'subgroup':
        if not args.prime or not args.generator or not args.public_key:
            parser.error('Subgroup mode requires --prime, --generator, and --public-key')
        
        partial_key, modulus = small_subgroup_attack(args.prime, args.generator, args.public_key)
        
        if partial_key and args.output:
            with open(args.output, 'w') as f:
                f.write(f"partial_private_key = {partial_key} (mod {modulus})\n")
            print(f"[*] Results written to {args.output}")
    
    elif args.mode == 'invalid-curve':
        result = invalid_curve_attack_sim()
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(f"result = {result}\n")
            print(f"[*] Results written to {args.output}")
    
    elif args.mode == 'weak-params':
        if not args.prime or not args.generator:
            parser.error('Weak-params mode requires --prime and --generator')
        
        is_secure, issues = weak_parameter_analysis(args.prime, args.generator)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(f"secure = {is_secure}\n")
                f.write(f"issues = {issues}\n")
            print(f"[*] Analysis written to {args.output}")
    
    elif args.mode == 'logjam':
        if not args.prime or not args.generator or not args.public_key:
            parser.error('Logjam mode requires --prime, --generator, and --public-key')
        
        result = logjam_attack_sim(args.prime, args.generator, args.public_key)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(f"logjam_result = {result}\n")
            print(f"[*] Results written to {args.output}")
    
    elif args.mode == 'mitm':
        result = man_in_the_middle_sim()
        
        if args.output:
            with open(args.output, 'w') as f:
                for key, value in result.items():
                    f.write(f"{key} = {value}\n")
            print(f"[*] MITM simulation written to {args.output}")

if __name__ == "__main__":
    main()
