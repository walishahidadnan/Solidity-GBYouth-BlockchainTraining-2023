from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives import padding


def generateRSAKeyPair():
    privateKey = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
    )
    publicKey = privateKey.public_key()
    return privateKey, publicKey


def RSAEncrypt(publicKey, text):
    cipherText = publicKey.encrypt(text, padding=PKCS1v15())
    return cipherText


def RSADecrypt(privateKey, cipherText):
    plainText = privateKey.decrypt(cipherText, padding=PKCS1v15())
    return plainText


def generateDSAKeyPair():
    privateKey = dsa.generate_private_key(key_size=1024)
    publicKey = privateKey.public_key()
    return privateKey, publicKey


def DSASign(privateKey, message):
    signature = privateKey.sign(
        message,
        algorithm=hashes.SHA256()
    )
    return signature

def DSAVerify(publicKey, message, signature):
    try:
        publicKey.verify(
            signature,
            message,
            hashes.SHA256()
        )
        return True
    except :
        return False

def main():
    RSAprivateKey, RSApublicKey = generateRSAKeyPair()
    message = "Message for RSA algorithm"
    plainText = message.encode()
    cipherText = RSAEncrypt(RSApublicKey, plainText)
    decryptedText = RSADecrypt(RSAprivateKey, cipherText)

    print("RSA Public Key:", RSApublicKey)
    print("RSA Private Key:", RSAprivateKey)
    print("Plain Text:", plainText.decode())
    print("Cipher Text:", cipherText)
    print("Decrypted Text:", decryptedText)


DSAPrivateKey, DSAPublicKey = generateDSAKeyPair()
message = b"Message for DSA algorithm"
signature = DSASign(DSAPrivateKey, message)
verified = DSAVerify(DSAPublicKey, message, signature)

print("DSA Public Key:", DSAPublicKey)
print("DSA Private Key:", DSAPrivateKey)
print("Message:", message)
print("Signature:", signature)
print("Verified:", verified)

# Calling the main function
main()









# e necessary module from cryptographic library
# from cryptography.hazmat.primitives.asymetric import rsa, dsa
# from cryptography.hazmat.primitives import serialization, hashes
# from cryptography.hazmat.primitives.asymetric.padding import PKCS1v15
# from cryptography.hazmat.primitives import padding

# import hashlib
# import SHA256
# import Crypto_Random
# for Crypto_Hash import SHA256
# import Crypto.Signature.DSS as DSS

# # take a plain text
# message = "a quick brown fox"

# # step to generate public key and private key
# random_generator = Crypto.Random.new().read
# rsa_key = rsa.generate(2048,random_generator)

# public_key = rsa_key.publickey()
# private_key = rsa_key

# # encrypt and decrypt the message using RSA
# encrypted_message = rsa.encrypt(message.encode(), public_key)
# decrypted_message = rsa.decrypt(encrypted_message, private_key).decode()
# print ("RSA Decrypted Message:, decrypted_message")

# # generate a public key and a private key for a pair DSA
# dsa_key = DSS.generate(2048)

# public_key_dsa = dsa_key.public_key
# private_key = dsa_key

# # generate a signature for the message and verify it using DSS
# hash_message = SHA256.new(message.encode())
# signer = DSS.new(private_key, 'fips-186-3')

# signature = signer.sign(hash_message)

# verifier = DSS.new(public_key_dsa, 'fips-186-3')
# try:
#     verifier.verify(hash_message, signature)
#     print ("DSA Signature verification: successful")
# except ValueError:
#     print ("DSA Signature verification; failed")

# #############################################################################################


# import rsa
# import Crypto.Random
# from Crypto.Hash import SHA256
# import Crypto.Signature.DSS as DSS

# # Step a: Take a plain text message
# message = "A quick brown fox"

# # Step b: Generate the public and private key pair for RSA
# random_generator = Crypto.Random.new().read
# rsa_key = rsa.generate(2048, random_generator)

# public_key = rsa_key.publickey()
# private_key = rsa_key

# # Step c: Encrypt and decrypt the message using RSA
# encrypted_message = rsa.encrypt(message.encode(), public_key)
# decrypted_message = rsa.decrypt(encrypted_message, private_key).decode()

# print("RSA Decrypted Message:", decrypted_message)

# # Step d: Generate a public and private key pair for DSA
# dsa_key = DSS.generate(2048)

# public_key_dsa = dsa_key.public_key
# private_key_dsa = dsa_key

# # Step e: Generate a signature for the message and verify it using DSA
# hash_message = SHA256.new(message.encode())
# signer = DSS.new(private_key_dsa, 'fips-186-3')

# signature = signer.sign(hash_message)

# verifier = DSS.new(public_key_dsa, 'fips-186-3')
# try:
#     verifier.verify(hash_message, signature)
#     print("DSA Signature Verification: Successful")
# except ValueError:
#     print("DSA Signature Verification: Failed")



