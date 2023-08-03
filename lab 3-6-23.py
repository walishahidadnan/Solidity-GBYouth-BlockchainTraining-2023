import hashlib

file_path = "./message1.bin"

def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

online_hash = input("Enter the online hash: ")

imported_hash = calculate_file_hash(file_path)

if online_hash == imported_hash:
    print("The hashes match!")
else:
    print("The hashes do not match.")
