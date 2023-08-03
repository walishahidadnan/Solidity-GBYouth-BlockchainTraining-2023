import hashlib

fileHashString = 'c27783392976304d9ec296c6cf318f4145e780d02b78c679347e93408553a59c'

with open('./text.txt', 'rb') as file:
    binaryData = file.read()

sha256_hash = hashlib.sha256(binaryData).hexdigest()

if fileHashString == sha256_hash:
    print('Hash matches')
else:
    print('Hash does not match')

# Effect avalanche

with open('text.txt', 'rb') as textFile:
    fileOneBinary = textFile.read()

fileOneHash = hashlib.sha256(fileOneBinary).hexdigest()

print('Hash before changing:', fileOneHash)

with open('textcopy.txt', 'rb') as textfileChange:
    fileTwoBinary = textfileChange.read()

fileTwoHash = hashlib.sha256(fileTwoBinary).hexdigest()
print('Hash after changing:', fileTwoHash)

if fileTwoHash == fileOneHash:
    print('Hash of both files match')
else:
    print('Hash of both files do not match')

# Last task

with open('message1.bin', 'rb') as messageOne:
    messageOneBinary = messageOne.read()

with open('message2.bin', 'rb') as messageTwo:
    messageTwoBinary = messageTwo.read()

print('')
print('Hashing message with md5')
print(hashlib.md5(messageOneBinary).hexdigest())
print(hashlib.md5(messageTwoBinary).hexdigest())
print('')
print('Hashing message with sha1')
print(hashlib.sha1(messageOneBinary).hexdigest())
print(hashlib.sha1(messageTwoBinary).hexdigest())
