from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime, GCD, inverse
import math

# Generate custom RSA key pairs, ensuring a shared factor p
def generate_rsa_keypair_with_shared_p(p, bits=2048):
    q = getPrime(bits // 2)  
    n = p * q  
    e = 65537  
    phi = (p - 1) * (q - 1) 
    d = inverse(e, phi)  
    return RSA.construct((n, e, d, p, q))

# Generate RSA key pairs with unshared factors (First revision)
def generate_rsa_keypair(bits=2048):
    key = RSA.generate(bits)
    return key

# Find the shared factor between two RSA moduli via GCD
def find_shared_factor(n1, n2):
    return math.gcd(n1, n2)

# Recovering private keys with shared factors (Second revision_check)
def recover_private_key(n, e, shared_factor):
    q = n // shared_factor  # Compute another prime q from the modulus n and the sharing factor p
    phi = (shared_factor - 1) * (q - 1) 
    d = pow(e, -1, phi)  # caculate the private key d
    return d

def main():
    p = getPrime(1024) 

    key1 = generate_rsa_keypair_with_shared_p(p, 2048)
    key2 = generate_rsa_keypair_with_shared_p(p, 2048)

    print(f"Key 1 modulus (n1): {key1.n}")
    print(f"Key 2 modulus (n2): {key2.n}")

    shared_factor = find_shared_factor(key1.n, key2.n)
    print(f"Found shared factor (p): {shared_factor}")

    private_key = recover_private_key(key1.n, key1.e, shared_factor)
    print(f"Recovered private key (d): {private_key}")


if __name__ == "__main__":
    main()
