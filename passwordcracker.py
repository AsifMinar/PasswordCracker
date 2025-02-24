'''
#step 1

import hashlib

def make_md5_hash(password):
    hash_object = hashlib.md5(password.encode())
    return hash_object.hexdigest()

test_password = "password123"
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
                return password 
    return None 
    
target = "098f6bcd4621d373cade4e832627b4f6" 
print("Target Hash:", target)
result = brute_force_crack(target)
print("Cracked Password:", result)

'''
#step 3 

import hashlib

def make_md5_hash(password):
    return hashlib.md5(password.encode()).hexdigest()

def word_list_crack(target_hash, file_path):
    # Checks every word in the file to see if its hash matches
    try:
        with open(file_path, 'r') as file:  # Open the word list
            for line in file:
                password = line.strip()  # Remove extra spaces or newlines
                if make_md5_hash(password) == target_hash:
                    return password  # Found it!
                
        return None  # Not in the list
    except FileNotFoundError:
        print("File not found! Make sure 'wordlist.txt' exists.")
        return None

# Test it
target = "482c811da5d5b4bc6d497ffa98491e38"  # Hash for "password123"
result = word_list_crack(target, "wordlist.txt")
print("Cracked Password: ", result)