from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

def generateECDSAKeyPair():
    privateKey = ec.generate_private_key(ec.SECP256K1())
    publicKey = privateKey.public_key()
    return privateKey, publicKey

def ECDSASign(privateKey, message):
    signature = privateKey.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def ECDSAVerify(publicKey, message, signature):
    try:
        publicKey.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except:
        return False

def main():
    ECDSAPrivateKey, ECDSAPublicKey = generateECDSAKeyPair()
    message = b"Message for ECDSA algorithm"  # Convert the message to bytes
    signature = ECDSASign(ECDSAPrivateKey, message)
    verified = ECDSAVerify(ECDSAPublicKey, message, signature)

    print("ECDSA:")
    print("ECDSA Public Key:", ECDSAPublicKey)
    print("ECDSA Private Key:", ECDSAPrivateKey)
    print("Message:", message.decode())  # Decode the message to display it as a string
    print("Signature:", signature)
    print("Verification:", verified)

# Calling the main function
main()
