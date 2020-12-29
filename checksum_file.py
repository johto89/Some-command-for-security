# !/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import os.path
 
filename = input("Enter the input file name: ")

def sha256_chk(filename):
    sha256_hash = hashlib.sha256()
    with open(filename,"rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
        print(sha256_hash.hexdigest())
        
def md5_chk(filename):
    md5_hash = hashlib.md5()
    with open(filename,"rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096),b""):
            md5_hash.update(byte_block)
        print(md5_hash.hexdigest())
        

def main():
    if os.path.isfile(filename):
        hashfunction = input("Enter the input hash function(md5 or sha256): ")
        if hashfunction == "md5":
            md5_chk(filename)
        elif hashfunction == "sha256":
            sha256_chk(filename)
        else:
            Raise("{} is an invalid hash function. Please Enter MD5 or SHA256")
    else:
        print ("File not exist")

if __name__ == "__main__":
    main()



