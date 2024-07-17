import hashlib
import sys
import pyfiglet

ascii_banner = pyfiglet.figlet_format("Hashing Cracker")
print(ascii_banner)

print("Algorithms Available: MD5 | SHA1 | SHA224 | SHA512 | SHA256 | SHA384")

hash_type = str(input("What's the the hash type?"))
wordlist_location = str(input("Enter Wordlist location: "))
hash = str(input("Enter Hash: "))

word_list = open(f"{wordlist_location}").read()
lists = word_list.splitlines()

import hashlib

for word in lists:
    if hash_type == "MD5":
        hash_object = hashlib.md5(f"{word}".encode('utf-8'))
        hashed = hash_object.hexdigest()
        if hash == hashed:
            print(f"\033[1;32m HASH FOUND: {word} \n")
    elif hash_type == "SHA1":
        hash_object = hashlib.sha1(f"{word}".encode('utf-8'))
        hashed = hash_object.hexdigest()
        if hash == hashed:
            print(f"\033[1;32m HASH FOUND: {word} \n")
    elif hash_type == "SHA224":
        hash_object = hashlib.sha224(f"{word}".encode('utf-8'))
        hashed = hash_object.hexdigest()
        if hash == hashed:
            print(f"\033[1;32m HASH FOUND: {word} \n")
    elif hash_type == "SHA512":
        hash_object = hashlib.sha512(f"{word}".encode('utf-8'))
        hashed = hash_object.hexdigest()
        if hash == hashed:
            print(f"\033[1;32m HASH FOUND: {word} \n")
    elif hash_type == "SHA256":
        hash_object = hashlib.sha256(f"{word}".encode('utf-8'))
        hashed = hash_object.hexdigest()
        if hash == hashed:
            print(f"\033[1;32m HASH FOUND: {word} \n")      
    elif hash_type == "SHA384":
        hash_object = hashlib.sha384(f"{word}".encode('utf-8'))
        hashed = hash_object.hexdigest()
        if hash == hashed:
            print(f"\033[1;32m HASH FOUND: {word} \n")
    else:
        print("Please Choose from the given options.")
