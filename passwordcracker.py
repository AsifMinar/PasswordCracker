#step 1

import hashlib

def make_md5_hash(password):
    hash_object = hashlib.md5(password.encode())
    return hash_object.hexdigest()

test_password = "password"
hashed = make_md5_hash(test_password)
print("password is: ", test_password)
print("MD5 hash of password is: ", hashed)

#step 2

import hashlib
import itertools 
import string    

def make_md5_hash(password):
    return hashlib.md5(password.encode()).hexdigest()

def brute_force_crack(target_hash):
    
    letters = string.ascii_lowercase 
    for length in range(1, 5):  
        for guess in itertools.product(letters, repeat=length):
            password = ''.join(guess)  
            if make_md5_hash(password) == target_hash:
                return password  # Found it!
    return None  # Didn’t find it
    