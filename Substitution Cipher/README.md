## What's this about?
Substitution ciphers replace each letter with another letter, creating a scrambled message. Once considered secure, these ciphers can now be easily cracked using frequency analysis
This repo includes:

substitution.py: Python code implementing cryptanalysis techniques for breaking substitution ciphers
substitution.html: An interactive web tool that visualizes the breaking process
Substitution-Output: Sample encrypted messages to test the breaking algorithm

The Breaking Methods
This project demonstrates 2 main techniques for breaking substitution ciphers:

Frequency Analysis: Using letter frequency patterns in English to make initial guesses about the cipher mapping
Hill Climbing Algorithm: An optimization technique that iteratively improves the key by making small changes and keeping those that produce more English-like text
