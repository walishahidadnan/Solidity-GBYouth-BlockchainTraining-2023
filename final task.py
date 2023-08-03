import hashlib

def hashing(msg):
    sha256 = hashlib.sha256()
    sha256.update(msg.encode('utf-8'))
    return sha256.hexdigest()

def prog1(sender, recipient, subject, body, nonce):
    msg = sender + recipient + subject + body + str(nonce)
    attempt = 0
    while True:
        attempt += 1
        hash_value = hashing(msg)
        if hash_value[:2] == "ff":
            break
        nonce += 1
        msg = sender + recipient + subject + body + str(nonce)

    return attempt, hash_value

def prog2(sender, recipient, subject, body, nonce):
    msg = sender + recipient + subject + body + str(nonce)
    attempts = 0
    while True:
        attempts += 1
        hash_value = hashing(msg)
        if hash_value[:4] == "ffff":
            break
        nonce += 1 
        msg = sender + recipient + subject + body + str(nonce)
    return attempts, hash_value

sender_email = "Shahid2019adnan@gmail.com"
recipient_email = "nust_blockchain@nust.com"
email_subject = "Final Assessment"
email_body = "This is the test of the final module 1."
nonce = 0

attempts_prog, hash_value_prog = prog1(sender_email, recipient_email, email_subject, email_body, nonce)
print("Task 1 - Attempts:", attempts_prog)
print("Task 1 - Hash Value:", hash_value_prog)

attempts_prog2, hash_value_prog2 = prog2(sender_email, recipient_email, email_subject, email_body, nonce)
print("Task 2 - Attempts:", attempts_prog2)
print("Task 2 - Hash Value:", hash_value_prog2)
