import hashlib
import bcrypt 
print(hashlib.sha1(b"Shahid_adnan").hexdigest())
print(hashlib.sha256(b"Shahid_adnan").hexdigest())
print(hashlib.sha512(b"Shahid_adnan").hexdigest())
print(hashlib.md5(b"Shahid_adnan").hexdigest())



password = "Hello"
salt = bcrypt. gensalt()
bcrypt_hash = bcrypt.hashpw(password.encode(), salt)
print ("bcrypt Hash:", bcrypt_hash)


text = "Hello"
ripemd160_hash = hashlib.new('ripemd160', text.encode()). hexdigest()
print("RIPEMD_160 Hash:", ripemd160_hash)


text = "SVB saw no other solution but to sell its holdings of bonds at a loss in order to honor its depositors, which resulted in a $1.9 billion hole in its balance sheet. To bolster its finances and plug the hole, it planned to raise $2.25 billion by issuing new shares, which backfired instead and caused a staggering $42 billion withdrawal from depositors in a single day."
ripemd160_hash = hashlib.new('ripemd160', text. encode()). hexdigest()
print("RIPEMD_160:", ripemd160_hash)


text = "SVB saw no other idea but to sell its bonds at a loss in order to honor its depositors, which resulted in a $1.9 billion hole in its balance sheet. To bolster its finances and plug the hole, it planned to raise $2.25 billion by issuing new shares, which backfired instead and caused a staggering $42 billion withdrawal from depositors in a single day."
ripemd160_hash = hashlib. new('ripemd160', text. encode()).hexdigest()
print("RIPEMD_160hash:", ripemd160_hash)




name_bytes = "c27783392976304d9ec296c6cf318f4145e780d02b78c679347e93408553a59c"
SHA256_hash = hashlib.new('sha256',name_bytes.encode()).hexdigest()

if SHA256_hash == "c27783392976304d9ec296c6cf318f4145e780d02b78c679347e93408553a59c":
    print ("hash is matched")

else: print ("hash not matched")