import argparse
import hashlib
from itertools import product
import time
from passlib.hash import sha512_crypt, nthash
import threading
from colorama import Fore, init

init(autoreset=True)
def generate_combinations(chars, min_length, max_length=22):
    for length in range(min_length, max_length + 1):
        for combo in product(chars, repeat=length):
            yield ''.join(combo)


def md5_hash(string):
    return hashlib.md5(string.encode()).hexdigest()


def sha1_hash(string):
    return hashlib.sha1(string.encode()).hexdigest()


def sha256_hash(string):
    return hashlib.sha256(string.encode()).hexdigest()


def sha512_unix_hash(string):
    return sha512_crypt.using(rounds=5000).hash(string)


def nt_hash(string):
    return nthash.hash(string)


def print_current_password(hash_type, target_hash, current_word):
    print(f'\rTYPE: {hash_type} | TARGET: {target_hash} | TRYING: {current_word}', end='', flush=True)


def brute_force(target_hash, hash_type, chars, min_length, max_length, safety_pause=None):
    counter = 0
    for word in generate_combinations(chars, min_length, max_length):
        print_current_password(hash_type, target_hash, word)

        if hash_type == 'md5':
            computed_hash = md5_hash(word)
        elif hash_type == 'sha1':
            computed_hash = sha1_hash(word)
        elif hash_type == 'sha256':
            computed_hash = sha256_hash(word)
        elif hash_type == 'sha512_unix':
            if sha512_crypt.verify(word, target_hash):
                return word
        elif hash_type == 'nt':
            computed_hash = nt_hash(word)
        else:
            raise ValueError("Unsupported hash type")

        if computed_hash == target_hash:
            return word

        counter += 1
        if safety_pause and counter % 699999 == 0:
            time.sleep(safety_pause)


def worker(target_hash, hash_type, chars, min_length, max_length, safety_pause, results):
    try:
        res = brute_force(target_hash, hash_type, chars, min_length, max_length, safety_pause)
        results.append(res)
    except Exception as e:
        print(f"Error in worker thread: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Brute force a hash from a file. Supports MD5, SHA-1, SHA-256, SHA-512(UNIX), and Windows NT.")
    parser.add_argument("--hash", required=True, help="File containing the hash to be brute-forced.")
    parser.add_argument("--hash-type", required=True, choices=['md5', 'sha1', 'sha256', 'sha512_unix', 'nt'],
                        help="Type of hashing algorithm.")
    parser.add_argument("--length", type=int, default=4, choices=range(4, 9),
                        help="Minimum password length to start brute-forcing. Default is 4, can be set between 4 and 8.")
    parser.add_argument("--threads", type=int, default=1, choices=[1, 2, 3, 4],
                        help="Number of threads to use for brute-forcing. Default is 1. Max is 4.")
    parser.add_argument("--safety", action="store_true",
                        help="Enables a throttle mechanism to reduce CPU usage during brute-forcing.")

    args = parser.parse_args()

    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*'
    min_length = args.length

    safety_pause = 1.35 if args.safety else None

    try:
        with open(args.hash, 'r') as file:
            target_hash = file.readline().strip()
    except FileNotFoundError:
        print("Error: Specified file not found.")
        exit(1)
    except PermissionError:
        print("Error: No permission to read the file.")
        exit(1)

    if not target_hash:
        print("Error: File is empty or contains no valid hash.")
        exit(1)

    results = []
    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker,
                             args=(target_hash, args.hash_type, chars, min_length, 22, safety_pause, results))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    if results and results[0]:
        print(f"\nMatch found for hash {target_hash}:{Fore.LIGHTBLUE_EX} {results[0]}")
    else:
        print(f"\nNo match found for hash {target_hash}.")
