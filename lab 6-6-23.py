# task 1
import hashlib

string_1 = "abc"
hash_1 = hashlib.sha256(string_1.encode()).hexdigest()
print("HASH1:", hash_1)

string_2 = "def"
hash_2 = hashlib.sha256(string_2.encode()).hexdigest()
print ("HASH2:", hash_2)

string_3 = "ghi"
hash_3 = hashlib.sha256(string_3.encode()).hexdigest()
print ("HASH3:", hash_3)

string_4 = "jkl"
hash_4 = hashlib.sha256(string_4.encode()).hexdigest()
print ("HASH4:", hash_4)

string_5 = "mno"
hash_5 = hashlib.sha256(string_5.encode()).hexdigest()
print ("HASH5:", hash_5)

string_6 = "pqr"
hash_6 = hashlib.sha256(string_6.encode()).hexdigest()
print ("HASH6:", hash_6)

string_7 = "stu"
hash_7 = hashlib.sha256(string_7.encode()).hexdigest()
print ("HASH7:", hash_7)

string_8 = "vwx"
hash_8 = hashlib.sha256(string_8.encode()).hexdigest()
print ("HASH8:", hash_8)

hash_A = hash_1 + hash_2  # No need to put "hash_1" and "hash_2" inside quotes
hash_A = hashlib.sha256(hash_A.encode()).hexdigest()
print("HASHA:", hash_A)

hash_B = "hash_3+hash_4"
hash_B = hashlib.sha256(hash_B.encode()).hexdigest()
print ("HASHB:", hash_B)

hash_C = "hash_5+hash_6"
hash_C = hashlib.sha256(hash_C.encode()).hexdigest()
print ("HASHC:", hash_C)

hash_D = "hash_7+hash_8"
hash_D = hashlib.sha256(hash_D.encode()).hexdigest()
print ("HASHD:", hash_D)

hash_A1 = hash_A + hash_B  # No need to put "hash_A" and "hash_B" inside quotes
hash_A1 = hashlib.sha256(hash_A1.encode()).hexdigest()
print("HASHA1:", hash_A1)

hash_A2 = "hash_C+hash_D"
hash_A2 = hashlib.sha256(hash_A2.encode()).hexdigest()
print ("HASHA2:", hash_A2)

root_hash = hash_A1 + hash_A2  # No need to put "hash_A1" and "hash_A2" inside quotes
root_hash = hashlib.sha256(root_hash.encode()).hexdigest()
print("ROOTHASH:", root_hash)


# task 2
import hashlib 
def calculate_block_hash(data):
    return hashlib.sha256(data).hexdigest()


file_path = "./Lab5-6-2023.pdf" 
with open(file_path, 'rb') as file_text:
    file_content = file_text.read()

block_size = len(file_content) // 8
blocks = [file_content[i:i+block_size] for i in range(0, len(file_content),block_size)] 

block_hashes = [calculate_block_hash(block) for block in blocks]


while len(block_hashes) > 1:
    next_level = []
    for i in range(0, len(block_hashes), 2):  # Correct the range function here
        left_child = block_hashes[i]  # Do not convert to bytes before hashing
        if i + 1 < len(block_hashes):
            right_child = block_hashes[i + 1]  # Do not convert to bytes before hashing
            nodal_hash = calculate_block_hash(right_child.encode() + left_child.encode())
            next_level.append(nodal_hash)
        else:
            next_level.append(left_child)
    block_hashes = next_level

merkel_root = block_hashes[0]
print("MERKEL ROOT:", merkel_root)
            



# task 3
import hashlib

def markleRoot(file_path):
    file = open("./Lab5-6-2023.pdf", "rb")
    content = file.read()

    listOfHashes = []
    # listOfTwoShes = []
    # listOfFourShes = []
    rootHash = ""

    blockSize = len(content) // 512
    dataBlocks = [content[i:i + blockSize] for i in range(0, len(content), blockSize)]
    print("blocksixe",len(dataBlocks))
    for x in range(len(dataBlocks)):
        stringToHash = hashlib.sha256(dataBlocks[x]).hexdigest()  # Remove encode() here
        listOfHashes.append(stringToHash)

    while len(listOfHashes) > 1:
        storedHashes = []
        for x in range(0, len(listOfHashes), 2):
            if x + 1 < len(listOfHashes):
                stringToHash = listOfHashes[x] + listOfHashes[x + 1]
            else:
                stringToHash = listOfHashes[x] + listOfHashes[x]
            stringToHash = hashlib.sha256(stringToHash.encode()).hexdigest()
            storedHashes.append(stringToHash)
        listOfHashes = storedHashes

    rootHash = listOfHashes[0]

    return rootHash

file_path = './Lab5-6-2023.pdf'
root_hash = markleRoot(file_path)
print(f"Root Hash: {root_hash}")