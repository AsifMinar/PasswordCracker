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



#step 4


import hashlib

def make_md5_hash(password):
    return hashlib.md5(password.encode()).hexdigest()

def build_rainbow_table(file_path):
    # Makes a dictionary of hashes and passwords
    table = {}
    try:
        with open(file_path, 'r') as file:
            for line in file:
                password = line.strip()
                hash_value = make_md5_hash(password)
                table[hash_value] = password  # Store hash: password pair
        return table
    except FileNotFoundError:
        print("File not found!")
        return {}

# Test it
table = build_rainbow_table("wordlist.txt")
print(f"Rainbow Table has {len(table)} entries")





#step 5


import hashlib

def make_md5_hash(password):
    return hashlib.md5(password.encode()).hexdigest()

def build_rainbow_table(file_path):
    table = {}
    try:
        with open(file_path, 'r') as file:
            for line in file:
                password = line.strip()
                hash_value = make_md5_hash(password)
                table[hash_value] = password
        return table
    except FileNotFoundError:
        print("File not found!")
        return {}

def rainbow_crack(target_hash, table):
    # Look up the hash in the table
    return table.get(target_hash)  # Returns password or None if not found

# Test it
target = "482c811da5d5b4bc6d497ffa98491e38"  # Hash for "password123"
table = build_rainbow_table("wordlist.txt")
result = rainbow_crack(target, table)
print(f"Target Hash: {target}")
print(f"Cracked Password: {result}")




#step 6

import hashlib

def make_hash(password, hash_type="md5"):
    # Makes a hash with the type you choose
    if hash_type == "md5":
        return hashlib.md5(password.encode()).hexdigest()
    elif hash_type == "sha1":
        return hashlib.sha1(password.encode()).hexdigest()
    elif hash_type == "sha256":
        return hashlib.sha256(password.encode()).hexdigest()
    else:
        print("Wrong hash type! Use md5, sha1, or sha256.")
        return None

# Test it
password = "password"
print(f"MD5: {make_hash(password, 'md5')}")
print(f"SHA-1: {make_hash(password, 'sha1')}")
print(f"SHA-256: {make_hash(password, 'sha256')}")

'''

import hashlib
import itertools
import string

def make_hash(password, hash_type="1"):
    if hash_type == "1":
        return hashlib.md5(password.encode()).hexdigest()
    elif hash_type == "2":
        return hashlib.sha1(password.encode()).hexdigest()
    elif hash_type == "3":
        return hashlib.sha256(password.encode()).hexdigest()
    else:
        print("Please type '1' for md5, '2' for sha1, '3' for  sha256!")
        return None

def brute_force_crack(target_hash, hash_type):
    letters = string.ascii_lowercase
    for length in range(1, 5):
        for guess in itertools.product(letters, repeat=length):
            password = ''.join(guess)
            if make_hash(password, hash_type) == target_hash:
                return password
    return None

def word_list_crack(target_hash, file_path, hash_type):
    try:
        with open(file_path, 'r') as file:
            for line in file:
                password = line.strip()
                if make_hash(password, hash_type) == target_hash:
                    return password
        return None
    except FileNotFoundError:
        print("File not found!")
        return None

def build_rainbow_table(file_path, hash_type):
    table = {}
    try:
        with open(file_path, 'r') as file:
            for line in file:
                password = line.strip()
                hash_value = make_hash(password, hash_type)
                table[hash_value] = password
        return table
    except FileNotFoundError:
        print("File not found!")
        return {}

def rainbow_crack(target_hash, table):
    return table.get(target_hash)

# Menu
print("Welcome to Password Cracker!")
print("1. Brute Force")
print("2. Word List")
print("3. Rainbow Table")
choice = input("Pick to type--->\n 1 \n 2 \n 3: ")
hash_type = input("Hash type---> \n '1' for md5, \n '2' for sha1, \n '3' for sha256: ").lower()
target_hash = input("Enter the hash to crack: ")

if choice == "1":
    result = brute_force_crack(target_hash, hash_type)
elif choice == "2":
    file_path = input("Path to wordlist.txt: ")
    result = word_list_crack(target_hash, file_path, hash_type)
elif choice == "3":
    file_path = input("Path to wordlist.txt for rainbow table: ")
    table = build_rainbow_table(file_path, hash_type)
    result = rainbow_crack(target_hash, table)
else:
    print("Bad choice!")
    result = None

if result:
    print(f"Password found: {result}")
else:
    print("Couldn’t crack it!")
    
        
   


