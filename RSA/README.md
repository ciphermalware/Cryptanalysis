# RSA Attack by ciphermalware

Hello world. This is a little project that shows how RSA encryption can be broken when it's not implemented correctly. Nothing malicious here - just educational stuff to understand cryptography better.

## What's This All About?

RSA is one of those super popular encryption algorithms that keeps our data safe online. But when it's not set up properly, like using keys that are too small, it can be cracked

This repo includes:

- **rsa_attack.py**: Python code showing different ways to break RSA
- **rsa_attack_visualization.html**: An interactive web tool to see these attacks in action
- **screenshot.png**: What it looks like when running

## The Attacks

This project demonstrates 2 main ways RSA can be broken:

1. **Factorization Attack**: Breaking RSA by finding the prime factors of the public modulus, which is easy when the primes are small like in this example
2. **Common Modulus Attack**: Recovering a message when it's encrypted with the same modulus but different exponents


## Note

Real world RSA uses massive prime numbers like hundreds of digits long, that can't be factored with my current computing power. The examples here use small numbers to see the attacks work.

