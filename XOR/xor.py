import itertools
import string
import binascii
from collections import Counter

def xor_bytes(data, key):
    """XOR data with key"""
    if isinstance(key, int):
        key = bytes([key])  
    
    key_length = len(key)
    return bytes(data[i] ^ key[i % key_length] for i in range(len(data)))

def is_printable(data):
    """Check if all characters in the data are printable ASCII."""
    return all(32 <= b <= 126 or b in (9, 10, 13) for b in data)

def score_english(plaintext):
    """Score how likely the text is to be english"""
    # Character frequency in english text 
    char_freq = {
        'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7, 's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3,
        'l': 4.0, 'u': 2.8, 'c': 2.8, 'm': 2.4, 'w': 2.4, 'f': 2.2, 'g': 2.0, 'y': 2.0, 'p': 1.9, 'b': 1.5,
        'v': 1.0, 'k': 0.8, 'j': 0.15, 'x': 0.15, 'q': 0.1, 'z': 0.07, ' ': 15.0
    }
    
    # Common english words
    common_words = [
        "the", "and", "that", "have", "for", "not", "with", "you", "this", "but", "his", "from", 
        "they", "say", "her", "she", "will", "one", "all", "would", "there", "their", "what", 
        "out", "about", "who", "get", "which", "when", "make", "can", "like", "time", "just", 
        "him", "know", "take", "people", "into", "year", "your", "good", "some", "could", "them", 
        "see", "other", "than", "then", "now", "look", "only", "come", "its", "over", "think", 
        "also", "back", "after", "use", "two", "how", "our", "work", "first", "well", "way", 
        "even", "new", "want", "because", "any", "these", "give", "day", "most", "us"
    ]
    
    # Convert to lowercase for analysis
    if isinstance(plaintext, bytes):
        try:
            text = plaintext.decode('utf-8', errors='ignore').lower()
        except:
            return -1  
    else:
        text = plaintext.lower()
    
    # Calculate character frequency score
    score = 0
    char_count = Counter(text)
    for char, count in char_count.items():
        freq = count / len(text) * 100
        if char.lower() in char_freq:
            # Calculate how close the frequency is to expected english
            score += min(freq, char_freq[char.lower()])
    
    # Bonus for common english words
    words = text.split()
    for word in words:
        if word.lower() in common_words:
            score += 2
    
    # Penalty for non-printable characters
    if isinstance(plaintext, bytes):
        for b in plaintext:
            if not (32 <= b <= 126 or b in (9, 10, 13)):
                score -= 10
    
    # Bonus for spaces with appropriate frequency 
    space_freq = text.count(' ') / len(text) * 100 if text else 0
    if 10 <= space_freq <= 25:
        score += 10
    
    return score

def break_single_byte_xor(ciphertext):
    """Break a single-byte XOR cipher."""
    best_score = -float('inf')
    best_key = None
    best_plaintext = None
    
    # Try all possible single-byte keys 
    for key in range(256):
        plaintext = xor_bytes(ciphertext, key)
        
        # Skip outputs with too many nonprintable characters
        if not is_printable(plaintext):
            continue
            
        score = score_english(plaintext)
        
        if score > best_score:
            best_score = score
            best_key = key
            best_plaintext = plaintext
    
    return {
        'key': best_key,
        'key_hex': hex(best_key)[2:].zfill(2),
        'plaintext': best_plaintext.decode('utf-8', errors='ignore') if best_plaintext else None,
        'score': best_score
    }

def hamming_distance(bytes1, bytes2):
    """Calculate the Hamming distance between two byte sequences."""
    if len(bytes1) != len(bytes2):
        raise ValueError("Byte sequences must be of equal length")
    
    distance = 0
    for b1, b2 in zip(bytes1, bytes2):
        # XOR the bytes and count the '1' bits
        xor_result = b1 ^ b2
        # Count bits set to 1 using bin() and count()
        distance += bin(xor_result).count('1')
    
    return distance

def find_key_size(ciphertext, min_size=2, max_size=40, num_samples=4):
    """
    Determine the most likely key size by calculating 
    normalized Hamming distances between blocks of ciphertext
    """
    results = []
    
    for key_size in range(min_size, min(max_size + 1, len(ciphertext) // 2)):
        distances = []
        
        for i in range(num_samples - 1):
            if (i + 2) * key_size <= len(ciphertext):
                block1 = ciphertext[i * key_size:(i + 1) * key_size]
                block2 = ciphertext[(i + 1) * key_size:(i + 2) * key_size]
                distance = hamming_distance(block1, block2)
                normalized_distance = distance / key_size  # Normalize by key size
                distances.append(normalized_distance)
        
        if distances:
            avg_distance = sum(distances) / len(distances)
            results.append((key_size, avg_distance))
    
    # Sort by normalized distance (ascending)
    results.sort(key=lambda x: x[1])
    
    return [size for size, _ in results[:3]]  # Return top 3 candidates

def transpose_blocks(ciphertext, key_size):
    """Transpose blocks of ciphertext for analysis"""
    blocks = []
    
    for i in range(key_size):
        block = bytes([ciphertext[j] for j in range(i, len(ciphertext), key_size)])
        blocks.append(block)
    
    return blocks

def break_repeating_key_xor(ciphertext, min_key_size=2, max_key_size=40):
    """Break a repeatingkey XOR cipher"""
    # First, determine likely key sizes
    key_sizes = find_key_size(ciphertext, min_key_size, max_key_size)
    
    best_overall_score = -float('inf')
    best_overall_result = None
    
    # Try each key size
    for key_size in key_sizes:
        
        blocks = transpose_blocks(ciphertext, key_size)
        
        # Break each block as single-byte XOR
        key_bytes = []
        for block in blocks:
            result = break_single_byte_xor(block)
            if result['key'] is not None:
                key_bytes.append(result['key'])
            else:
                # If any block can't be broken, try a different key size
                key_bytes = None
                break
        
        if key_bytes:
            # Construct the full key
            key = bytes(key_bytes)
            
            # Try decrypting with this key
            plaintext = xor_bytes(ciphertext, key)
            score = score_english(plaintext)
            
            if score > best_overall_score:
                best_overall_score = score
                best_overall_result = {
                    'key': key,
                    'key_hex': binascii.hexlify(key).decode('ascii'),
                    'plaintext': plaintext.decode('utf-8', errors='ignore'),
                    'score': score,
                    'key_size': key_size
                }
    
    return best_overall_result

def break_xor_with_known_plaintext(ciphertext, known_plaintext):
    """Break XOR encryption if a portion of plaintext is known"""
    if len(known_plaintext) > len(ciphertext):
        raise ValueError("Known plaintext cannot be longer than ciphertext")
    
    # XOR the known plaintext with the corresponding portion of ciphertext
    # to recover that portion of the key
    if isinstance(known_plaintext, str):
        known_plaintext = known_plaintext.encode('utf-8')
    
    partial_key = xor_bytes(ciphertext[:len(known_plaintext)], known_plaintext)
    
    # Try to determine the key length by looking for patterns
    potential_lengths = []
    
    # Look for repeating patterns in the partial key
    for length in range(1, len(partial_key) // 2 + 1):
        chunks = [partial_key[i:i+length] for i in range(0, len(partial_key), length)]
        if len(chunks) >= 2 and all(chunk == chunks[0] for chunk in chunks if len(chunk) == length):
            potential_lengths.append((length, chunks[0]))
    
    results = []
    
    if potential_lengths:
        # Sort by length 
        potential_lengths.sort(key=lambda x: x[0])
        
        for length, repeated_key in potential_lengths:
            # Decrypt using the repeated key
            plaintext = xor_bytes(ciphertext, repeated_key)
            score = score_english(plaintext)
            
            results.append({
                'key': repeated_key,
                'key_hex': binascii.hexlify(repeated_key).decode('ascii'),
                'plaintext': plaintext.decode('utf-8', errors='ignore'),
                'score': score,
                'key_size': length
            })
    
    if results:
        # Return the best result by score
        return max(results, key=lambda x: x['score'])
    
    # If no repeating pattern found, try a general approach
    return break_repeating_key_xor(ciphertext)

def decrypt_xor(ciphertext, key):
    """Decrypt XOR-encrypted ciphertext using the provided key"""
    if isinstance(key, str):
        # Handle keys in different formats
        if key.startswith('0x'):
            key = bytes.fromhex(key[2:])
        elif all(c in string.hexdigits for c in key):
            key = bytes.fromhex(key)
        else:
            key = key.encode('utf-8')
    elif isinstance(key, int):
        key = bytes([key])
    
    plaintext = xor_bytes(ciphertext, key)
    return plaintext.decode('utf-8', errors='ignore')

def break_xor(ciphertext, known_plaintext=None):
    """
    Attempt to break XOR encryption using various methods
    
    Args:
        ciphertext: The encrypted data 
        known_plaintext: Optional known plaintext for known plaintext attack
        
    Returns:
        Dictionary with key, plaintext, and other information
    """
    # Try single-byte XOR first
    single_byte_result = break_single_byte_xor(ciphertext)
    
    # If we have known plaintext, try that approach
    if known_plaintext:
        kpa_result = break_xor_with_known_plaintext(ciphertext, known_plaintext)
        
        # Compare scores and take the best result
        if kpa_result and kpa_result['score'] > single_byte_result['score']:
            print("[+] Successfully broke cipher using known plaintext attack")
            return kpa_result
    
 
    if single_byte_result['score'] > 50:  
        print("[+] Successfully broke cipher using single-byte XOR analysis")
        return single_byte_result
    
    
    repeating_key_result = break_repeating_key_xor(ciphertext)
    
    if repeating_key_result:
        print(f"[+] Successfully broke cipher using repeating-key XOR analysis (key size: {repeating_key_result['key_size']})")
        return repeating_key_result
    
    # If all methods failed or produced poor results, return the best one
    if single_byte_result['score'] > (repeating_key_result['score'] if repeating_key_result else -float('inf')):
        print("[*] Best guess is single-byte XOR, but confidence is low")
        return single_byte_result
    else:
        print("[*] Best guess is repeating-key XOR, but confidence is low")
        return repeating_key_result

def hex_to_bytes(hex_string):
    """Convert a hex string to bytes."""
    if hex_string.startswith('0x'):
        hex_string = hex_string[2:]
    return bytes.fromhex(hex_string)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Break XOR encryption')
    parser.add_argument('--file', help='Path to file with ciphertext')
    parser.add_argument('--text', help='Ciphertext as string')
    parser.add_argument('--hex', help='Ciphertext as hex string')
    parser.add_argument('--known', help='Known plaintext for known-plaintext attack')
    parser.add_argument('--decrypt', action='store_true', help='Decrypt mode (requires --key)')
    parser.add_argument('--key', help='Key for decrypt mode (as hex or string)')
    
    args = parser.parse_args()
    
    if args.decrypt and args.key:
        # Decrypt mode
        if args.file:
            with open(args.file, 'rb') as f:
                ciphertext = f.read()
        elif args.hex:
            ciphertext = hex_to_bytes(args.hex)
        elif args.text:
            ciphertext = args.text.encode('utf-8')
        else:
            parser.error("No ciphertext provided. Use --file, --text, or --hex")
            
        plaintext = decrypt_xor(ciphertext, args.key)
        print(f"Decrypted text: {plaintext}")
    
    else:
        # Code breaking mode
        if args.file:
            with open(args.file, 'rb') as f:
                ciphertext = f.read()
        elif args.hex:
            ciphertext = hex_to_bytes(args.hex)
        elif args.text:
            ciphertext = args.text.encode('utf-8')
        else:
            parser.error("No ciphertext provided. Use --file, --text, or --hex")
        
        result = break_xor(ciphertext, args.known)
        
        print("\n=== Results ===")
        print(f"Key (hex): {result['key_hex']}")
        if isinstance(result['key'], bytes) and all(32 <= b <= 126 for b in result['key']):
            print(f"Key (text): {result['key'].decode('ascii')}")
        print(f"Key size: {result.get('key_size', 1)}")
        print(f"Score: {result['score']}")
        print("\nDecrypted text:")
        print(result['plaintext'])
