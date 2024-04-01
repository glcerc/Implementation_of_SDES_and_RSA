import random
import time

"""Checks if the input string can be converted to a valid integer."""
def is_valid_int(input_str):
    try:
        int(input_str)
        return True
    except ValueError:
        return False

"""Function to check whether a number is prime"""
def is_prime(number):
    if number < 2:
        return False
    if number == 2:
        return True
    if number % 2 == 0:
        return False
    for i in range(3, int(number ** 0.5) + 1, 2):
        if number % i == 0:
            return False
    return True

"""Function to calculate multiplicative inverse"""
def mod_inverse(e, phi):
    for d in range(2, phi):
        if (d * e) % phi == 1:
            return d
    raise ValueError("Modular inverse does not exist")


"""Function to calculate greatest common divisor"""
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

"""Function to generate prime number"""
def generate_prime(keysize):
    min_value = 2 ** (keysize - 1)
    max_value = (2 ** keysize) - 1
    while True:
        prime = random.randrange(min_value, max_value) | 1
        if is_prime(prime):
            return prime

"""Function to generate public and private kyes"""
def generate_keys(keysize):
    p = generate_prime(keysize // 2)
    q = generate_prime(keysize // 2)
    while p == q:
        q = generate_prime(keysize // 2)
    n = p * q
    totient_n = (p - 1) * (q - 1)
    e = random.randrange(2, totient_n)
    while gcd(e, totient_n) != 1:
        e = random.randrange(2, totient_n)

    d = mod_inverse(e, totient_n)
    return (e, n), (d, n)

"""Function to generate RSA key with the keysize given by the user"""
def rsa_key_generation():
    print("Generating RSA key pairs...")
    keysize = int(input("Enter the key size: "))
    public_key, private_key = generate_keys(keysize)
    print(f"Public Key: (e={public_key[0]}, n={public_key[1]})")
    print(f"Private Key: (d={private_key[0]}, n={private_key[1]})")

"""Function to perform RSA encryption and decryption with user's messages"""
def rsa_encryption_decryption():
    print("Demonstrating RSA Encryption and Decryption...")

    # Generate RSA keys
    keysize = 16
    public_key, private_key = generate_keys(keysize)

    # Get plaintext message from user
    message = input("Enter the message to encrypt: ")
    print(f"Original Message: {message}")

    # Encrypt message with RSA
    ciphertext = rsa_encrypt(message, public_key)
    print(f"Encrypted Message: {ciphertext}")

    # Decrypt message with RSA
    decrypted_message = rsa_decrypt(ciphertext, private_key)
    print(f"Decrypted Message: {decrypted_message}")

# RSA Encryption function
def rsa_encrypt(message, public_key):
    ciphertext = [pow(ord(char), public_key[0], public_key[1]) for char in message]
    return ciphertext

# RSA Decryption function
def rsa_decrypt(ciphertext, private_key):
    decrypted_message = ''.join(chr(pow(char, private_key[0], private_key[1])) for char in ciphertext)
    return decrypted_message

"""Function to check RSA correctnesss for 10 inputs"""
def test_rsa_correctness():
    inputs = ["Test message 1", "Test message 2", "Test message 3", "Test message 4", "Test message 5",
              "Test message 6", "Test message 7", "Test message 8", "Test message 9", "Test message 10"]

    for i, message in enumerate(inputs):
        public_key, private_key = generate_keys(16)
        ciphertext = rsa_encrypt(message, public_key)
        decrypted_message = rsa_decrypt(ciphertext, private_key)
        print(f"Test {i + 1}:")
        print("Original Message:", message)
        print("Decrypted Message:", decrypted_message)
        print()

"""Function to measure RSA performance for 3 different key sizes"""
def measure_rsa_performance(key_sizes=[16, 24, 28]):
    for key_size in key_sizes:
        print(f"Key Size: {key_size} bits")

        # Measure key generation time
        key_generation_times = []
        for _ in range(10):
            start_time = time.time()
            generate_keys(key_size)
            key_generation_time = time.time() - start_time
            key_generation_times.append(key_generation_time)
        avg_key_generation_time = sum(key_generation_times) / len(key_generation_times)
        print(f"Average Key Generation Time: {avg_key_generation_time:.5f} seconds")

        # Measure encryption and decryption times
        encryption_times = []
        decryption_times = []
        public_key, private_key = generate_keys(key_size)
        plaintext = "This is plaintext" * 100
        for _ in range(10):
            # Encryption time measurement
            start_time = time.time()
            ciphertext = rsa_encrypt(plaintext, public_key)
            encryption_time = time.time() - start_time
            encryption_times.append(encryption_time)

            # Decryption time measurement
            start_time = time.time()
            decrypted_text = rsa_decrypt(ciphertext, private_key)
            decryption_time = time.time() - start_time
            decryption_times.append(decryption_time)

        avg_encryption_time = sum(encryption_times) / len(encryption_times)
        avg_decryption_time = sum(decryption_times) / len(decryption_times)
        print(f"Average Encryption Time: {avg_encryption_time:.5f} seconds")
        print(f"Average Decryption Time: {avg_decryption_time:.5f} seconds")
        print()


"""S-DES Implementation"""
class SimplifiedDES:
    def __init__(self):
        self.P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
        self.P8 = [6, 3, 7, 4, 8, 5, 10, 9]
        self.IP = [2, 6, 3, 1, 4, 8, 5, 7]
        self.EP = [4, 1, 2, 3, 2, 3, 4, 1]
        self.P4 = [2, 4, 3, 1]
        self.IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]
        self.S0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
        self.S1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]
        #Attributes for key generation
        self.key = None
        self.K1 = None
        self.K2 = None

    def key_generation(self, key):
        # Apply P10 permutation
        permuted_key = [key[i - 1] for i in self.P10]

        # Split the key and apply LS-1
        left, right = permuted_key[:5], permuted_key[5:]
        left_shifted = left[1:] + left[:1]
        right_shifted = right[1:] + right[:1]

        # Apply P8 permutation to create K1
        self.K1 = [(left_shifted + right_shifted)[i - 1] for i in self.P8]

        # Apply LS-2 to both halves
        left_shifted_twice = left_shifted[2:] + left_shifted[:2]
        right_shifted_twice = right_shifted[2:] + right_shifted[:2]

        # Apply P8 permutation to create K2
        self.K2 = [(left_shifted_twice + right_shifted_twice)[i - 1] for i in self.P8]

    def fk(self, half_block, subkey):
        expanded_half = [half_block[i - 1] for i in self.EP]
        # XOR with subkey
        xor_result = [bit ^ k for bit, k in zip(expanded_half, subkey)]

        # Split for S-boxes
        left_half = xor_result[:4]
        right_half = xor_result[4:]

        # S-box substitutions
        row = left_half[0] * 2 + left_half[3]
        col = left_half[1] * 2 + left_half[2]
        left_sub = self.S0[row][col]

        row = right_half[0] * 2 + right_half[3]
        col = right_half[1] * 2 + right_half[2]
        right_sub = self.S1[row][col]

        # Convert S-box outputs to 2-bit sequences
        sbox_output = [left_sub >> 1, left_sub & 1, right_sub >> 1, right_sub & 1]

        # Final permutation P4
        final_result = [sbox_output[i - 1] for i in self.P4]

        # Return result
        return final_result

    def switch(self, data):
        return data[4:] + data[:4]

    def divide_into_blocks(self, message):
        blocks = []
        for i in range(0, len(message), 8):
            blocks.append(message[i:i+8])
        return blocks

    def string_to_binary(self, message):
        return ''.join(format(ord(char), '08b') for char in message)

    def binary_to_string(self, binary_data):
        return ''.join(chr(int(binary_data[i:i + 8], 2)) for i in range(0, len(binary_data), 8))

    def encrypt(self, message, key):
        # Convert the message to binary
        binary_message = self.string_to_binary(message)

        # Generate keys
        self.key_generation(key)

        # Encrypt block by block
        encrypted_message = ''
        for i in range(0, len(binary_message), 8):
            block = binary_message[i:i + 8]
            block = [int(bit) for bit in block]  # Convert string to list of bits
            encrypted_block = self.encrypt_block(block)
            encrypted_message += ''.join(map(str, encrypted_block))

        return encrypted_message

    def decrypt(self, binary_data, key):
        # Generate keys
        self.key_generation(key)

        # Decrypt block by block
        decrypted_message = ''
        for i in range(0, len(binary_data), 8):
            block = binary_data[i:i + 8]
            block = [int(bit) for bit in block]  # Convert string to list of bits
            decrypted_block = self.decrypt_block(block)
            decrypted_message += ''.join(map(str, decrypted_block))

        # Convert binary to string
        return self.binary_to_string(decrypted_message)

    def encrypt_block(self, block):
        # Initial permutation
        permuted_block = [block[i - 1] for i in self.IP]

        # Split the block into left and right halves
        left, right = permuted_block[:4], permuted_block[4:]

        # First function fK with K1
        fk_output = self.fk(right, self.K1)
        left = [l ^ f for l, f in zip(left, fk_output)]

        # Switch function
        combined = self.switch(left + right)

        # Second function fK with K2
        left, right = combined[:4], combined[4:]
        fk_output = self.fk(right, self.K2)
        left = [l ^ f for l, f in zip(left, fk_output)]

        # Final permutation
        return [(left + right)[i - 1] for i in self.IP_inv]

    def decrypt_block(self, block):

        # Initial permutation
        permuted_block = [block[i - 1] for i in self.IP]

        # Split the block into left and right halves
        left, right = permuted_block[:4], permuted_block[4:]

        # First function fK with K2
        fk_output = self.fk(right, self.K2)
        left = [l ^ f for l, f in zip(left, fk_output)]

        # Switch function
        combined = self.switch(left + right)

        # Second function fK with K1
        left, right = combined[:4], combined[4:]
        fk_output = self.fk(right, self.K1)
        left = [l ^ f for l, f in zip(left, fk_output)]

        # Combine the left and right halves before the final permutation
        preoutput = left + right

        # Final permutation (Inverse of Initial Permutation)
        decrypted_block = [preoutput[i - 1] for i in self.IP_inv]

        # Return the decrypted block
        return decrypted_block

"""Convert binary string to ASCII text."""
def binary_to_ascii(binary_str):
    return ''.join(chr(int(binary_str[i:i + 8], 2)) for i in range(0, len(binary_str), 8))


"""Function to measure S-DES performance and to test for 10 inputs """
def measure_sdes_performance():
    num_iterations = 10
    workload_size = 1000

    print(f"\nNumber of iterations for each operation: {num_iterations}")
    print(f"Workload size for each operation: {workload_size}")

    sdes = SimplifiedDES()

    # Measure S-DES key generation time
    key_generation_times = []
    print("Generating S-DES keys:")
    for i in range(num_iterations):
        start_time = time.perf_counter()
        for _ in range(workload_size):
            key = [random.randint(0, 1) for _ in range(10)]
            sdes.key_generation(key)
        elapsed_time = (time.perf_counter() - start_time) / workload_size
        key_generation_times.append(elapsed_time)
        print(f"Key {i + 1} generation average time: {elapsed_time:.6f} seconds")
    avg_key_generation_time = sum(key_generation_times) / num_iterations
    print(f"\nAverage Key Generation Time: {avg_key_generation_time:.6f} seconds\n")


    test_cases = [[random.randint(0, 1) for _ in range(8)] for _ in range(num_iterations)]

    # Measure S-DES encryption time
    encryption_times = []
    ciphertexts = []
    print("Testing encryption for the following plaintexts:")
    for index, plaintext in enumerate(test_cases):
        key = [random.randint(0, 1) for _ in range(10)]
        binary_plaintext = ''.join(map(str, plaintext))
        print(f"Plaintext {index + 1}: {binary_plaintext}")
        start_time = time.perf_counter()
        for _ in range(workload_size):
            encrypted_message = sdes.encrypt(binary_plaintext, key)
        elapsed_time = (time.perf_counter() - start_time) / workload_size
        encryption_times.append(elapsed_time)
        ciphertexts.append(encrypted_message)
        print(f"Ciphertext {index + 1}: {encrypted_message} average encryption time: {elapsed_time:.6f} seconds")
    avg_encryption_time = sum(encryption_times) / num_iterations
    print(f"\nAverage Encryption Time: {avg_encryption_time:.6f} seconds")

    # Measure S-DES decryption time
    decryption_times = []
    print("\nDecrypting the following ciphertexts:")
    for index, ciphertext in enumerate(ciphertexts):
        key = [random.randint(0, 1) for _ in range(10)]
        print(f"Ciphertext {index + 1}: {ciphertext}")
        start_time = time.perf_counter()
        for _ in range(workload_size):
            decrypted_message = sdes.decrypt(ciphertext, key)
        elapsed_time = (time.perf_counter() - start_time) / workload_size
        decryption_times.append(elapsed_time)

        # Checking the consistency of decrypted text and whether it's valid binary data
        consistent_decryption = all(bit in '01' for bit in decrypted_message)
        is_valid_binary = len(decrypted_message) % 8 == 0 and consistent_decryption


        print(f"Decrypted output contains non-binary characters: {not consistent_decryption}")

        if consistent_decryption and is_valid_binary:
            decrypted_text = binary_to_ascii(decrypted_message)
            print(f"Plaintext {index + 1}: {decrypted_text} average decryption time: {elapsed_time:.6f} seconds")
        else:
            print(f"Plaintext {index + 1}: Invalid binary data average decryption time: {elapsed_time:.6f} seconds")

    avg_decryption_time = sum(decryption_times) / num_iterations
    print(f"\nAverage Decryption Time: {avg_decryption_time:.6f} seconds")


"""Function to simulate communication between Alice and Bob"""
def alice_bob_communication_scenario():
    print("Alice and Bob are generating RSA key pairs...")
    alice_public, alice_private = generate_keys(16)
    bob_public, bob_private = generate_keys(16)

    print("Alice generates a secret S-DES key...")
    sdes_key = [random.randint(0, 1) for _ in range(10)]
    sdes_key_str = ''.join(map(str, sdes_key))
    print(f"Alice's secret S-DES key: {sdes_key_str}")

    print("Alice encrypts the S-DES key with Bob's public RSA key and sends it to Bob...")
    encrypted_sdes_key = rsa_encrypt(sdes_key_str, bob_public)

    print("Bob receives the encrypted S-DES key and decrypts it with his private RSA key...")
    decrypted_sdes_key_str = rsa_decrypt(encrypted_sdes_key, bob_private)
    decrypted_sdes_key = [int(bit) for bit in decrypted_sdes_key_str]
    print(f"Bob's decrypted S-DES key: {''.join(map(str, decrypted_sdes_key))}")

    # Simulate message exchange using S-DES
    sdes = SimplifiedDES()
    messages = ["Hello Bob!", "Hello Alice!", "How are you?", "I'm fine, thank you!"]
    print("\nAlice and Bob start exchanging messages using S-DES...")
    for msg in messages:
        # Alice sends a message to Bob
        encrypted_msg = sdes.encrypt(msg, sdes_key)
        encrypted_msg_str = ''.join(map(str, encrypted_msg))
        print(f"Alice sends: {encrypted_msg_str}")

        # Bob receives and decrypts the message
        decrypted_msg_bits = sdes.decrypt(encrypted_msg, sdes_key)
        decrypted_msg = sdes.decrypt(encrypted_msg,decrypted_sdes_key)
        print(f"Bob receives: {decrypted_msg}")


"""Function that generates a random S-DES key"""
def sdes_key_generation():
    print("Generating S-DES key...")
    key = [random.randint(0, 1) for _ in range(10)]
    print(f"S-DES Key: {''.join(map(str, key))}")

"""Function to perform S-DES encryption and decryption"""
def sdes_encryption_decryption(sdes):
    key = [random.randint(0, 1) for _ in range(10)]
    print(f"S-DES Key: {''.join(map(str, key))}")

    # Get plaintext message from user
    message = input("Enter the message to encrypt: ")
    print(f"Original Message: {message}")

    # Encrypt message with S-DES
    encrypted_message = sdes.encrypt(message, key)
    print(f"Encrypted Message: {encrypted_message}")

    # Decrypt message with S-DES
    decrypted_message = sdes.decrypt(encrypted_message, key)
    print(f"Decrypted Message: {decrypted_message}")


"""Main Function"""
def main():
    print("Welcome to our hand-generated cryptographic system!")
    print("What do you want to do with us?")
    sdes = SimplifiedDES()
    while True:
        print("\nPress 1 for executing RSA key generation,")
        print("Press 2 for RSA encryption-decryption,")
        print("Press 3 for S-DES key generation,")
        print("Press 4 for S-DES encryption and decryption,")
        print("Press 5 for producing Alice-Bob communication scenarios,")
        print("Press 6 to test and measure RSA performance,")
        print("Press 7 to test and measure S-DES performance,")
        print("Press 8 to exit.")

        answer_str = input("Enter your choice: ")

        if is_valid_int(answer_str):
            answer = int(answer_str)
            if answer == 1:
                rsa_key_generation()
            elif answer == 2:
                rsa_encryption_decryption()
            elif answer == 3:
                sdes_key_generation()
            elif answer == 4:
                sdes_encryption_decryption(sdes)
            elif answer == 5:
                alice_bob_communication_scenario()
            elif answer == 6:
                test_rsa_correctness()
                measure_rsa_performance()
            elif answer == 7:
                measure_sdes_performance()
            elif answer == 8:
                print("Exiting...")
                break
            else:
                print("Invalid choice. Please enter a number between 1 and 8.")
        else:
            print("Invalid input. Please enter a number.")


if __name__ == "__main__":
    main()
