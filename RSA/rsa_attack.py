import math
from sympy import isprime, gcd

def generate_weak_rsa_keys(bits=16):
    """Generate intentionally weak RSA keys for demonstration"""
    from random import getrandbits

    p = q = 2
    while not isprime(p):
        p = getrandbits(bits) | 1  
    while not isprime(q) or q == p:
        q = getrandbits(bits) | 1
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 65537  
    while gcd(e, phi) != 1:
        e += 2
    
    d = pow(e, -1, phi)
    
    return (e, n), (d, n), (p, q)

def encrypt(message, public_key):
    """Encrypt a message using RSA public key"""
    e, n = public_key
    if message >= n:
        raise ValueError("Message too large for the key size")
    return pow(message, e, n)

def decrypt(ciphertext, private_key):
    """Decrypt a message using RSA private key"""
    d, n = private_key
    return pow(ciphertext, d, n)

def break_rsa_small_n(n):
    """Factor n to break RSA when n is small"""
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return i, n // i
    return None, None

def break_rsa_known_factors(n, e, p, q):
    """Demonstrate breaking RSA when factors are known"""
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return d

def common_modulus_attack(c1, c2, e1, e2, n):
    """Demonstrate common modulus attack when same message is encrypted with different exponents"""
    # Extended euclidean algorithm 
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    g, s, t = extended_gcd(e1, e2)
    
    if g != 1:
        return None  # Remmmeber that exponents must be coprime
    
    if t < 0:
        t = -t
        c2 = pow(c2, -1, n)
    
    if s < 0:
        s = -s
        c1 = pow(c1, -1, n)
    
    # Calculate message
    m = (pow(c1, s, n) * pow(c2, t, n)) % n
    return m

# Demonstration
def main():
    print("RSA Vulnerability Demonstration\n")
    
    # Generate intentionally weak keys
    public_key, private_key, factors = generate_weak_rsa_keys()
    e, n = public_key
    d, _ = private_key
    p, q = factors
    
    print(f"Generated weak RSA parameters:")
    print(f"p = {p}, q = {q}")
    print(f"n = p*q = {n}")
    print(f"Public key (e, n): ({e}, {n})")
    print(f"Private key (d, n): ({d}, {n})")
    
    # Encrypt and decrypt a message
    message = 42
    print(f"\nOriginal message: {message}")
    
    ciphertext = encrypt(message, public_key)
    print(f"Encrypted message: {ciphertext}")
    
    decrypted = decrypt(ciphertext, private_key)
    print(f"Decrypted message: {decrypted}")
    
    # Break RSA by factoring n
    print("\nBreaking RSA by factoring n:")
    found_p, found_q = break_rsa_small_n(n)
    if found_p:
        print(f"Factors found: p = {found_p}, q = {found_q}")
        
        derived_d = break_rsa_known_factors(n, e, found_p, found_q)
        print(f"Derived private exponent d = {derived_d}")
        
        # Decrypting message
        derived_decrypted = decrypt(ciphertext, (derived_d, n))
        print(f"Decrypted using derived key: {derived_decrypted}")
    else:
        print("Factorization failed")
    
    # Common modulus attack demonstration
    print("\nCommon modulus attack demonstration:")
    e2 = 3  
    while gcd(e2, (p-1)*(q-1)) != 1:
        e2 += 2
        
    ciphertext2 = encrypt(message, (e2, n))
    print(f"Same message encrypted with e2 = {e2}: {ciphertext2}")
    
    # Here it performs the attack
    recovered = common_modulus_attack(ciphertext, ciphertext2, e, e2, n)
    if recovered:
        print(f"Message recovered using common modulus attack: {recovered}")
    else:
        print("Common modulus attack failed")

if __name__ == "__main__":
    main()
