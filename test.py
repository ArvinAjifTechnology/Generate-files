from hashlib import sha512
from Crypto.PublicKey import RSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import ECC

# Helper to count bit differences
def bit_diff(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))

# 1. Buat hash SHA-512 dari dua pesan berbeda 1 bit
msg1 = b"CryptographyIsCool"
msg2 = b"CryptographyIsFool"  # hanya 1 bit beda pada huruf C -> F

hash1 = sha512(msg1).digest()
hash2 = sha512(msg2).digest()

# 2. RSA Key Pair
rsa_key = RSA.generate(4096)
rsa_signer = pkcs1_15.new(rsa_key)

# 3. Tanda tangan dengan RSA (menggunakan SHA-512 hash)
rsa_signature1 = rsa_signer.sign(SHA512.new(msg1))
rsa_signature2 = rsa_signer.sign(SHA512.new(msg2))

rsa_avalanche = bit_diff(rsa_signature1, rsa_signature2)

# 4. ECDSA Key Pair
ecdsa_key = ECC.generate(curve='P-521')
ecdsa_signer = DSS.new(ecdsa_key, 'fips-186-3')

ecdsa_signature1 = ecdsa_signer.sign(SHA512.new(msg1))
ecdsa_signature2 = ecdsa_signer.sign(SHA512.new(msg2))

ecdsa_avalanche = bit_diff(ecdsa_signature1, ecdsa_signature2)

# Panjang output signature dan avalanche effect
rsa_sig_bits = len(rsa_signature1) * 8
ecdsa_sig_bits = len(ecdsa_signature1) * 8

rsa_avalanche_percent = rsa_avalanche / rsa_sig_bits * 100
ecdsa_avalanche_percent = ecdsa_avalanche / ecdsa_sig_bits * 100

rsa_sig_bits, rsa_avalanche, rsa_avalanche_percent, ecdsa_sig_bits, ecdsa_avalanche, ecdsa_avalanche_percent


print("=== Avalanche Effect Analysis ===")
print(f"RSA Signature Length      : {rsa_sig_bits} bits")
print(f"RSA Bit Differences       : {rsa_avalanche} bits")
print(f"RSA Avalanche Percentage  : {rsa_avalanche_percent:.2f}%\n")

print(f"ECDSA Signature Length    : {ecdsa_sig_bits} bits")
print(f"ECDSA Bit Differences     : {ecdsa_avalanche} bits")
print(f"ECDSA Avalanche Percentage: {ecdsa_avalanche_percent:.2f}%")
