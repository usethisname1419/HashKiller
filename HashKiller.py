#!/usr/bin/env python3

import psutil
import argparse
import hashlib
from itertools import product
import time
from passlib.hash import sha512_crypt, nthash
import threading
from colorama import Fore, init

print_lock = threading.Lock()
init(autoreset=True)

shutdown_event = threading.Event()
match_found_event = threading.Event()
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
    with print_lock:
        print(f'\rTYPE: {hash_type} | TARGET: {target_hash} | TRYING: {current_word}', end='')
        print("\033[K", end='', flush=True)

def brute_force(target_hash, hash_type, chars, min_length, max_length, success_event, safety_pause=None):
    counter = 0

    for word in generate_combinations(chars, min_length, max_length):
        if shutdown_event.is_set() or success_event.is_set():
            return

        print_current_password(hash_type, target_hash, word)

        if hash_type == 'md5':
            computed_hash = md5_hash(word)
        elif hash_type == 'sha1':
            computed_hash = sha1_hash(word)
        elif hash_type == 'sha256':
            computed_hash = sha256_hash(word)
        elif hash_type == 'sha512_unix':
            if sha512_crypt.verify(word, target_hash):
                success_event.set()
                with print_lock:
                    print(f"\nMatch found for hash {target_hash}:{Fore.LIGHTBLUE_EX} {word}")
                    time.sleep(2)
                return word
        elif hash_type == 'nt':
            computed_hash = nt_hash(word)
        else:
            raise ValueError("Unsupported hash type")

        if computed_hash == target_hash:
            success_event.set()
            match_found_event.set()
            time.sleep(1)
            with print_lock:
                print(f"\nMatch found for hash {target_hash}:{Fore.LIGHTBLUE_EX} {word}")

            return word

        counter += 1
        if safety_pause:
            if safety_pause == 1 and counter % 699999 == 0:
                time.sleep(1.35)
            elif safety_pause == 2 and counter % 699999 == 0:
                time.sleep(2)
            elif safety_pause == 3 and counter % 199999 == 0:
                time.sleep(1.5)


def resource_printer():
    while not shutdown_event.is_set():
        cpu, mem = resource_usage()
        with print_lock:

            print(f'\n\rCPU Usage: {cpu}%    Memory Usage: {mem}%', end='', flush=True)
            print("\033[F", end='', flush=True)
        time.sleep(1)
        if match_found_event.is_set():
            break
def resource_usage():
    cpu_percent = psutil.cpu_percent(interval=1)
    memory_info = psutil.virtual_memory()
    return cpu_percent, memory_info.percent

def crack_hash(target_hash, hash_type, chars, min_length, max_length, safety_pause=None):
    results = []
    threads = []
    try:
        for _ in range(args.threads):
            t = threading.Thread(target=brute_force,
                                 args=(target_hash, hash_type, chars, min_length, max_length, safety_pause))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

    except KeyboardInterrupt:
        print("\nInitiating graceful shutdown. Please wait...")
        shutdown_event.set()
        for t in threads:
            t.join()

    finally:
        if args.threads > 1:
            t_printer.join()

    results.append(brute_force(target_hash, args.hash_type, chars, min_length, 22, safety_pause))
    return results


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
    parser.add_argument("--safety", type=int, choices=[1, 2, 3], default=None,
                        help="Choose a safety level to reduce CPU usage during brute-forcing. Safety levels 1, 2, 3")

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

    try:
        success_event = threading.Event()  #success event to signal threads to stop

        threads = []

        for _ in range(args.threads):
            t = threading.Thread(target=brute_force,
                                 args=(target_hash, args.hash_type, chars, min_length, 22, success_event, safety_pause))
            t.start()
            threads.append(t)

        if args.threads > 1:
            t_printer = threading.Thread(target=resource_printer)
            t_printer.start()

        for t in threads:
            t.join()

        if args.threads > 1:
            t_printer.join()

        results = brute_force(target_hash, args.hash_type, chars, min_length, 22, success_event, safety_pause)
        if results:
            print(f"\nMatch found for hash {target_hash}:{Fore.LIGHTBLUE_EX} {results}")

    except KeyboardInterrupt:
        print("\nInitiating graceful shutdown. Please wait...")
        success_event.set()  #success event to stop threads
        for t in threads:
            t.join()
        if args.threads > 1:
            t_printer.join()

    if not success_event.is_set():
        print(f"\nNo match found for hash {target_hash}.")
