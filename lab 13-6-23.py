from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
import hashlib
import random



def generateTxid():
    random_integer = random.randint(1, 1000000)
    hash_obj = hashlib.sha256(str(random_integer).encode()) 
    return hash_obj.hexdigest()



def generateInput():
    prevTxid = generateTxid()
    prevOutputIndex = random.randint(1, 5)
    return prevTxid, prevOutputIndex



def generateOutput():
    recipientAddress = 'recipient_address_' + str(random.randint(1, 100))
    amount = round(random.uniform(0.001, 1.8), 8)
    return recipientAddress, amount



def generateTransactionFee():
    return round(random.uniform(0.0001, 0.001), 8)



def generateRandomTransaction():
    txid = generateTxid()
    inputPrevTxid, inputPrevOutputIndex = generateInput()
    outputRecipientAddress, outputAmount = generateOutput()
    transactionFee = generateTransactionFee()
    return txid, inputPrevTxid, inputPrevOutputIndex, outputRecipientAddress, outputAmount, transactionFee



def concatenateString(txid, inputPrevTxid,inputPrevOutputIndex, outputRecipientAddress,outputAmount, transactionFee):
    transactionData = str(txid) + str(inputPrevTxid) + str(inputPrevOutputIndex) + str(outputRecipientAddress) + str(outputAmount) + str(transactionFee)
    return transactionData.encode()



def generateECDSAKeyPair():
    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key, 



def ECDSASign(privateKey, message):
    signature = privateKey.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature



def ECDSAVerify(publicKey, message,signature):
    try:
        publicKey.verify(signature, message,ec.ECDSA(hashes.SHA256()))
        return True
    except:
        return False
    


def main():
    txid, inputPrevTxid, inputPrevOutputIndex, outputRecipientAddress, outputAmount, transactionFee = generateRandomTransaction()
    transactionData = concatenateString(txid, inputPrevTxid, inputPrevOutputIndex, outputRecipientAddress, outputAmount, transactionFee)
    transactionDataSHA256Hashed = hashlib.sha256(transactionData).hexdigest()
    ECDSAPrivateKey, ECDSAPublicKey = generateECDSAKeyPair()
    signature = ECDSASign(ECDSAPrivateKey, transactionDataSHA256Hashed.encode()) 
    verified = ECDSAVerify(ECDSAPublicKey, transactionDataSHA256Hashed.encode(), signature) 

    print("ECDSA:")
    print("ECDSA Public Key:", ECDSAPublicKey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode())
    print("ECDSA Private Key:", ECDSAPrivateKey.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()).decode())
    print("transactionDataSHA256Hashed:", transactionDataSHA256Hashed)
    print("Signature:", signature.hex())
    print("Verification:", verified)



main()