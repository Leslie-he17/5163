from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime, inverse

# Generate custom RSA key pairs, ensuring a shared factor p
def generate_rsa_keypair_with_shared_p(p, bits=2048):
    q = getPrime(bits // 2) # Generate another random prime q
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1) # Calculate the Euler function φ(n)
    d = inverse(e, phi) # Calculate the private keyd
    return RSA.construct((n, e, d, p, q))

# Generate RSA key pairs with unshared factors
def generate_rsa_keypair(bits=2048):
    key = RSA.generate(bits)
    return key

# Find the shared factor between two RSA moduli via Euclidean algorithm - iterative method
def find_shared_factor(n1, n2):
    while n2:
        n1, n2 = n2, n1 % n2
    return n1

# Find shared factor among multiple RSA moduli
def find_shared_factor_among_multiple_moduli(moduli):
    shared_factor = moduli[0]
    # Calculate the GCD of each subsequent modulus with the current "shared factor"
    for modulus in moduli[1:]:
        shared_factor = find_shared_factor(shared_factor, modulus)
        # If GCD is found to be 1, there is no shared factor and can exit early
        if shared_factor == 1:
            return print('no common factor among those moduli')
    return shared_factor

# Recovering private keys with shared factors
def recover_private_key(n, e, shared_factor):
    q = n // shared_factor  # Compute another prime q from the modulus n and the sharing factor p
    phi = (shared_factor - 1) * (q - 1) 
    d = pow(e, -1, phi)  # caculate the private key d
    return d

# Encrypt message
def Encrypt_message(m,e,n):
    c = 1
    for i in range(e):
        c = (c*m) % n
    return c

# Decrypt message
def Decrypt_message(c,d,n):
    m_prime = 1
    exponent = d # Use the calculated private key index d
    base = c % n

    # modulo idempotent operation
    while exponent > 0:
        if exponent % 2 == 1:
            m_prime = (m_prime * base) % n
        exponent = exponent // 2
        base = (base * base) % n

    return m_prime

def main():
    # Generate shared prime p
    p = getPrime(1024) 

    # Generate shared p
    key1 = generate_rsa_keypair_with_shared_p(p, 2048)
    key2 = generate_rsa_keypair_with_shared_p(p, 3072)
    key3 = generate_rsa_keypair(1024)

    print(f"Key 1 modulus (n1): {key1.n}")
    print(f"Key 2 modulus (n2): {key2.n}")
    print(f"Key 3 modulus (n3): {key3.n}")

    shared_factor_12 = find_shared_factor(key1.n, key2.n)
    shared_factor_13 = find_shared_factor(key1.n, key3.n)

    # Output shared factor results
    if shared_factor_12 != 1:
        print(f"Shared factor between key1 and key2 (p): {shared_factor_12}")
    else:
        print("No shared factor between key1 and key2")

    if shared_factor_13 != 1:
        print(f"Shared factor between key1 and key3 (p): {shared_factor_13}")
    else:
        print("No shared factor between key1 and key3")

    # Recover Private Key
    if shared_factor_12 != 1:
         print(f"Shared factor between key1 and key2 (p): {shared_factor_12}")
         
         # Recover private key for key1
         private_key_recovered = recover_private_key(key1.n, key1.e, shared_factor_12)
         print(f"Recovered private key for key1 (d): {private_key_recovered}")
         
         # Encryption and decryption
         m = 5163
         print(f"Original message: {m}")

         # Encrypt the message
         encrypted_message = Encrypt_message(m, key1.e, key1.n)
         print(f"Encrypted message (ciphertext): {encrypted_message}")
        
         # Decrypt the message
         decrypted_message = Decrypt_message(encrypted_message, private_key_recovered, key1.n)
         print(f"Decrypted message: {decrypted_message}")
    
    else:
        print("No shared factor found")

if __name__ == "__main__":
    main()
