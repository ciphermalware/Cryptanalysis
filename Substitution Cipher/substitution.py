import re
from collections import Counter
import random
import string

def preprocess_text(text):
    """Remove non alphabetic characters and convert to uppercase"""
    return re.sub(r'[^A-Za-z]', '', text).upper()

def calculate_frequencies(text):
    """Calculate letter frequencies in the text"""
    freq = Counter(text)
    total = len(text)
    return {char: count / total for char, count in freq.items()}

def score_text(text, ngram_scores, n=2):
    """Score text based on n gram frequencies from english"""
    score = 0
    for i in range(len(text) - n + 1):
        ngram = text[i:i+n]
        if ngram in ngram_scores:
            score += ngram_scores[ngram]
    return score

def generate_ngram_scores(english_text, n=2):
    """Generate n-gram scores from sample nglish text"""
    ngrams = {}
    english_text = preprocess_text(english_text)
    for i in range(len(english_text) - n + 1):
        ngram = english_text[i:i+n]
        ngrams[ngram] = ngrams.get(ngram, 0) + 1
    
    total = sum(ngrams.values())
    return {ngram: count / total for ngram, count in ngrams.items()}

def apply_key(text, key):
    """Apply a substitution key to the text"""
    mapping = dict(zip(string.ascii_uppercase, key))
    return ''.join(mapping.get(c, c) for c in text)

def decrypt(ciphertext, key):
    """Decrypt ciphertext using the given key"""
    mapping = {}
    for i, char in enumerate(key):
        mapping[char] = string.ascii_uppercase[i]
    
    return ''.join(mapping.get(c, c) for c in ciphertext)

def random_key():
    """Generate a random substitution key"""
    alphabet = list(string.ascii_uppercase)
    random.shuffle(alphabet)
    return ''.join(alphabet)

def swap_letters(key, i, j):
    key_list = list(key)
    key_list[i], key_list[j] = key_list[j], key_list[i]
    return ''.join(key_list)

def hill_climbing(ciphertext, ngram_scores, iterations=10000):
   
    best_key = random_key()
    best_score = score_text(decrypt(ciphertext, best_key), ngram_scores)
    
    for _ in range(iterations):
       
        i, j = random.sample(range(26), 2)
        
        
        candidate_key = swap_letters(best_key, i, j)
        
        # Decrypt and score
        candidate_text = decrypt(ciphertext, candidate_key)
        candidate_score = score_text(candidate_text, ngram_scores)
        
        # If the new score is better keep the new key
        if candidate_score > best_score:
            best_key = candidate_key
            best_score = candidate_score
    
    return best_key, decrypt(ciphertext, best_key)

def break_substitution_cipher(ciphertext, english_sample=None):
    """Break a substitution cipher using frequency analysis and hill climbing"""
    ciphertext = preprocess_text(ciphertext)
    
    # If no English sample is provided, use a default one
    if not english_sample:
        english_sample = """
        The quick brown fox jumps over the lazy dog. The five boxing wizards jump quickly.
        To be or not to be, that is the question. Four score and seven years ago our fathers 
        brought forth on this continent a new nation, conceived in Liberty, and dedicated to 
        the proposition that all men are created equal. Ask not what your country can do for 
        you; ask what you can do for your country.
        """
    
    ngram_scores = generate_ngram_scores(english_sample, 2)
    
    # Run the hill climbing algorithm multiple times
    best_overall_key = None
    best_overall_score = float('-inf')
    best_overall_text = None
    
    for _ in range(5):  # Try 5 different starting points
        key, plaintext = hill_climbing(ciphertext, ngram_scores)
        
        score = score_text(plaintext, ngram_scores)
        if score > best_overall_score:
            best_overall_score = score
            best_overall_key = key
            best_overall_text = plaintext
    
    return best_overall_key, best_overall_text

if __name__ == "__main__":
    # Example usage
    plaintext = "Hello world, this is a substitution cipher example"
    
    # Create a random key for encryption
    key = random_key()
    print(f"Original key: {key}")
    
    # Encrypt the plaintext
    ciphertext = apply_key(preprocess_text(plaintext), key)
    print(f"Ciphertext: {ciphertext}")
    
    # Try to break the cipher
    best_key, decrypted = break_substitution_cipher(ciphertext)
    print(f"Recovered key: {best_key}")
    print(f"Decrypted text: {decrypted}")
