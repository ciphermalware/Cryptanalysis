# Vigenère Cipher Breaker

## What's this all about?
It's interesting that the Vigenère cipher was considered unbreakable for centuries, but today we can crack it using frequency analysis techniques. This project demonstrates how we can break Vigenère encryption without knowing the key.

This repo includes:
* **vigenere_breaking.py**: Python code showing how to crack the Vigenère cipher using statistical methods
* **vigenere_cipher_breaker.html**: An interactive web tool visualizing the breaking process
* **example_texts.txt**: Sample encrypted messages to practice cracking

## The Breaking Methods
This project demonstrates 2 main techniques for breaking Vigenère ciphers:

1. **Key Length Determination**: Using the Index of Coincidence to find the most likely key length
2. **Frequency Analysis**: Analyzing letter frequencies in each column to determine individual key characters

