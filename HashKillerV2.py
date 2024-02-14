#!/usr/bin/env python3
import concurrent.futures
import psutil
import argparse
import hashlib
from itertools import product
import time
from passlib.hash import sha512_crypt, nthash
import threading
from colorama import Fore, init
import zipfile
import sys

print_lock = threading.Lock()
init(autoreset=True)

shutdown_event = threading.Event()
match_found_event = threading.Event()
threads = []

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


def pkzip_crack(zipfile_path, password):
    try:
        with zipfile.ZipFile(zipfile_path, 'r') as zip_file:
            zip_file.extractall(pwd=password.encode())
            return password
    except Exception as e:
        return None


def print_current_password(hash_type, target_hash, current_word):
    with print_lock:
        sys.stdout.write("\r\033[K")  # Move cursor to the beginning of the line and clear it
        sys.stdout.write(f'TYPE: {hash_type} | TRYING: {current_word}')
        sys.stdout.flush()



def brute_force(target_hash, hash_type, chars, min_length, max_length, success_event, safety_pause=None):
    counter = 0
    computed_hash = None  # Assign a default value to computed_hash

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
        elif hash_type == 'pkzip':
            if pkzip_crack(target_hash, word):
                success_event.set()
                with print_lock:
                    print(f"\nMatch found for hash {target_hash}:{Fore.LIGHTBLUE_EX} {word}")
                    time.sleep(2)
                return word
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
    global threads
    results = []

    t_printer = None  # Initialize t_printer variable

    try:
        t_printer = threading.Thread(target=resource_printer)
        t_printer.start()

        for _ in range(args.threads):
            t = threading.Thread(target=brute_force,
                                 args=(target_hash, hash_type, chars, min_length, max_length, success_event,
                                       safety_pause))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

    except KeyboardInterrupt:
        print("\nInitiating graceful shutdown. Please wait...")
        shutdown_event.set()
        for t in threads:
            t.join()
        if t_printer:
            t_printer.join()

    finally:
        if not success_event.is_set():
            print(f"\nNo match found for hash {target_hash}.")

        if t_printer:
            t_printer.join()

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Brute force a hash from a file. Supports MD5, SHA-1, SHA-256, SHA-512(UNIX), Windows NT, and PKZIP.")
    parser.add_argument("--hash", required=True, help="File containing the hash to be brute-forced.")
    parser.add_argument("--hash-type", required=True, choices=['md5', 'sha1', 'sha256', 'sha512_unix', 'nt', 'pkzip'],
                        help="Type of hashing algorithm.")
    parser.add_argument("--length", type=int, default=4, choices=range(4, 12),
                        help="Minimum password length to start brute-forcing. Default is 4, can be set between 4 and 8.")
    parser.add_argument("--threads", type=int, default=1, choices=[1, 2, 3, 4],
                        help="Number of threads to use for brute-forcing. Default is 1. Max is 4.")
    parser.add_argument("--safety", type=int, choices=[1, 2, 3], default=None,
                        help="Choose a safety level to reduce CPU usage during brute-forcing. Safety levels 1, 2, 3")

    args = parser.parse_args()

    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*() -_+=?<>'
    min_length = args.length

    safety_pause = args.safety

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
        success_event = threading.Event()  # success event to signal threads to stop

        results = crack_hash(target_hash, args.hash_type, chars, min_length, 22, safety_pause)
        if results:
            print(f"\nMatch found for hash {target_hash}:{Fore.LIGHTBLUE_EX} {results}")


    except KeyboardInterrupt:

        print("\nInitiating graceful shutdown. Please wait...")

        success_event.set()  # success event to stop threads

        for t in threads:
            t.join()

    if not success_event.is_set():
        print(f"\nNo match found for hash {target_hash}.")

