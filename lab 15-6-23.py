import hashlib
import base58
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def generateECDSAKeyPair():
    privateKey = ec.generate_private_key(ec.SECP256K1(),default_backend())  # B
    publicKey = privateKey.public_key()
    return privateKey,publicKey

def bitCoinWalletAddress(publicKey):
    sha256Hash=hashlib.sha256(publicKey).digest()
    ripemd160Hash=hashlib.new('ripemd160',sha256Hash).digest()
    sha256Hash1=hashlib.sha256(ripemd160Hash).digest()
    sha256Hash2=hashlib.sha256(sha256Hash1).digest()
    network_bytes=b'00'
    net_rem_hash=network_bytes+ripemd160Hash
    checksum=sha256Hash2[:4]
    extended=net_rem_hash+checksum
    wallet_address=base58.b58encode(extended)  
    print("    HASH SHA256    : %s"%sha256Hash)
    print("    HASH RIPEMD160 : %s"%ripemd160Hash)
    print("    MainNet+RIPEMD : %s"%net_rem_hash)
    print("    HASH SHA256 1  : %s"%sha256Hash1)
    print("    HASH SHA256 2  : %s"%sha256Hash2)
    print("    HASH CHECK SUM : %s"%checksum)
    print("    EXTENDED  200  : %s"%extended)
    print("    Wallet Address : %s"%wallet_address.decode())

(privateKey,publicKey)=generateECDSAKeyPair()

public_bytes = publicKey.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint   #  C
    )

bitCoinWalletAddress(public_bytes)