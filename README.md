# Implementation of SDES and RSA

This repository contains an implementation of the RSA and Simplified DES cryptographic algorithms along with a command-line interface for executing various functionalities related to RSA key generation, encryption-decryption, S-DES key generation, encryption, decryption, and Alice-Bob communication scenarios.
# Functionality
# 1. RSA Key Generation
RSA key generation with customizable key size.
Implemented necessary functions such as primality test, gcd, and multiplicative inverse.
# 2. RSA Encryption and Decryption
Implementation of the RSA encryption and decryption algorithms.
# 3. Simplified DES
Random key generation of appropriate size.
Implementation of encryption and decryption according to the provided documentation (S-DES.pdf).
# 4. Testing
Correctness testing for RSA encryption-decryption and S-DES encryption-decryption.
Time measurement for:
RSA key generation for different key sizes.
RSA encryption and decryption.
S-DES key generation, encryption, and decryption.
# 5. Alice-Bob Communication Scenario
Simulation of Alice and Bob generating RSA key pairs and sharing public keys.
Alice generates a secret key, encrypts it with RSA, and sends it to Bob.
Alice and Bob use S-DES with the shared key to exchange messages.
# 6. Command-Line Interface
A simple CLI allowing the user to execute RSA key generation, RSA encryption-decryption, S-DES key generation, S-DES encryption, decryption, and Alice-Bob communication scenarios.
# Note
The block size of S-DES is 8 bits. Users can enter a larger message which will be divided into 8-bit blocks for encryption or decryption.
