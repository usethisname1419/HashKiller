import argparse
import hashlib
from itertools import product
import time

def generate_combinations(chars, min_length, max_length):
    for length in range(min_length, max_length + 1):
        for combo in product(chars, repeat=length):
            yield ''.join(combo)

def md5_hash(string):
    return hashlib.md5(string.encode()).hexdigest()

def sha1_hash(string):
    return hashlib.sha1(string.encode()).hexdigest()

def print_current_password(hash_type, target_hash, current_word):
    print(f'\rTYPE: {hash_type} | TARGET: {target_hash} | TRYING: {current_word}', end='', flush=True)





def brute_force(target_hash, hash_type, chars, min_length, max_length):

    for word in generate_combinations(chars, min_length, max_length):
        
        if hash_type == 'md5':
            computed_hash = md5_hash(word)
            print_current_password(hash_type, target_hash, word)  # Print details
            if computed_hash == target_hash:
                return word
            time.sleep(0.1)  # Slow it down
                
        elif hash_type == 'sha1':
            computed_hash = sha1_hash(word)
            print_current_password(hash_type, target_hash, word)  # Print details
            if computed_hash == target_hash:
                return word
            time.sleep(0.1)  # Slow it down
    return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Brute force hashes from a file.")
    parser.add_argument("--hash", required=True, help="File containing hashes to be brute-forced.")
    parser.add_argument("--hash-type", required=True, choices=['md5', 'sha1'], help="Type of hashing algorithm (md5 or sha1).")
    
    args = parser.parse_args()

    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
    min_length = 4
    max_length = 22

    with open(args.hash, 'r') as file:
        for line in file:
            target = line.strip()  # Trim whitespace to prevent hash mismatch
            result = brute_force(target, args.hash_type, chars, min_length, max_length)
            if result:
                print(f"\rMatch found for hash {target}: {result}        ")
                break   # Exit the loop as soon as a match is found
            else:
                print(f"\rNo match found for hash {target}.               ")
