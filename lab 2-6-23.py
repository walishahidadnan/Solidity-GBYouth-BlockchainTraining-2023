import hashlib
import bcrypt

#  Import libraries

# Take name as input
name = input("Enter your name:")

#  Convert name string to bytes
name_bytes = name.encode()
# we have to generate hashes
md5_hash = hashlib.md5(name_bytes).hexdigest()
sha1_hash = hashlib.sha1(name_bytes).hexdigest()
sha256_hash = hashlib.sha256(name_bytes).hexdigest()
sha512_hash = hashlib.sha512(name_bytes).hexdigest()
sha3_hash = hashlib.sha3_256(name_bytes).hexdigest()
blake2_hash = hashlib.blake2s(name_bytes).hexdigest()
bcrypt_salt = bcrypt.gensalt()
bcrypt_hash = bcrypt.hashpw(name_bytes, bcrypt_salt).decode()

print("MD5:", md5_hash)
print("SHA-1:", sha1_hash)
print("SHA-256:", sha256_hash)
print("SHA-512:", sha512_hash)
print("SHA-3 (SHA-3-256):", sha3_hash)
print("BLAKE2 (BLAKE2s):", blake2_hash)
print("bcrypt:", bcrypt_hash)
