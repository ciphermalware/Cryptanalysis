def vigenere_decrypt(ciphertext, key):
    plaintext = ""
    key_length = len(key)
    key = key.upper()
    
    for i in range(len(ciphertext)):
        char = ciphertext[i]
        if char.isalpha():
            if char.isupper():
                shift = ord(key[i % key_length]) - ord('A')
                decrypt_char = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            else:
                shift = ord(key[i % key_length]) - ord('A')
                decrypt_char = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            plaintext += decrypt_char
        else:
            plaintext += char
    
    return plaintext

def calculate_ioc(text):
    freq = {}
    for char in text.upper():
        if char.isalpha():
            freq[char] = freq.get(char, 0) + 1
    
    n = sum(freq.values())
    if n <= 1:
        return 0
    
    ioc = 0
    for count in freq.values():
        ioc += count * (count - 1)
    
    ioc /= n * (n - 1)
    return ioc * 26

def get_key_length(ciphertext, max_length=20):
    avg_iocs = []
    
    for key_len in range(1, max_length + 1):
        iocs = []
        
        for i in range(key_len):
            group = ""
            for j in range(i, len(ciphertext), key_len):
                if j < len(ciphertext) and ciphertext[j].isalpha():
                    group += ciphertext[j]
            
            if group:
                iocs.append(calculate_ioc(group))
        
        if iocs:
            avg_iocs.append((key_len, sum(iocs) / len(iocs)))
    
    avg_iocs.sort(key=lambda x: x[1], reverse=True)
    
   
    return [kl for kl, _ in avg_iocs[:3]]

def frequency_analysis(text):
    
    freq = {}
    for char in text.upper():
        if char.isalpha():
            freq[char] = freq.get(char, 0) + 1
    
    # Calculate percentages
    total = sum(freq.values())
    for char in freq:
        freq[char] = freq[char] / total
    
    return freq

def guess_key(ciphertext, key_length):
    eng_freqs = {
        'E': 0.12702, 'T': 0.09056, 'A': 0.08167, 'O': 0.07507, 'I': 0.06966,
        'N': 0.06749, 'S': 0.06327, 'H': 0.06094, 'R': 0.05987, 'D': 0.04253,
        'L': 0.04025, 'C': 0.02782, 'U': 0.02758, 'M': 0.02406, 'W': 0.02360,
        'F': 0.02228, 'G': 0.02015, 'Y': 0.01974, 'P': 0.01929, 'B': 0.01492,
        'V': 0.00978, 'K': 0.00772, 'J': 0.00153, 'X': 0.00150, 'Q': 0.00095,
        'Z': 0.00074
    }
    
    ordered_eng = "ETAOINSRHDLCUMWFGYPBVKJXQZ"
    key = ""
    
    for i in range(key_length):
        column = ""
        for j in range(i, len(ciphertext), key_length):
            if j < len(ciphertext) and ciphertext[j].isalpha():
                column += ciphertext[j].upper()
        
        # Calculate frequency for this column
        freq = frequency_analysis(column)
        
        # Try each possible shift 
        best_shift = 0
        best_chi_sq = float('inf')
        
        for shift in range(26):
            chi_sq = 0
            for char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                shifted_char = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                expected = eng_freqs.get(shifted_char, 0)
                observed = freq.get(char, 0)
                
                if expected > 0:
                    chi_sq += ((observed - expected) ** 2) / expected
            
            if chi_sq < best_chi_sq:
                best_chi_sq = chi_sq
                best_shift = shift
        
        key += chr(best_shift + ord('A'))
    
    return key

def crack_vigenere(ciphertext):
    clean_text = ''.join(c for c in ciphertext if c.isalpha())
    
    print("Finding potential key lengths...")
    key_lengths = get_key_length(clean_text)
    print(f"Most likely key lengths: {key_lengths}")
    
    results = []
    for kl in key_lengths:
        key = guess_key(clean_text, kl)
        plaintext = vigenere_decrypt(ciphertext, key)
        results.append((key, plaintext))
        print(f"Key length {kl} => Key: {key}")
        print(f"Sample decryption: {plaintext[:50]}...")
    
    return results

# Example 
if __name__ == "__main__":
    ciphertext = input("Enter Vigenère encrypted text: ")
    results = crack_vigenere(ciphertext)
    
    print("\nTop decryption candidates:")
    for i, (key, plaintext) in enumerate(results, 1):
        print(f"\n{i}. Key: {key}")
        print(f"Decryption: {plaintext[:100]}...")
        user_input = input("Show more? (y/n/all): ")
        if user_input.lower() == 'all':
            print(plaintext)
        elif user_input.lower() == 'y':
            print(plaintext[:300])
