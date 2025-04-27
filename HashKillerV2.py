#!/usr/bin/env python3
# The 'concurrent.futures' module was imported but not used in the code
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
import re

print_lock = threading.Lock()
init(autoreset=True)

shutdown_event = threading.Event()
match_found_event = threading.Event()
threads = []


def generate_combinations(chars, min_length, max_length=22):
    for length in range(min_length, max_length + 1):
        for combo in product(chars, repeat=length):
            yield ''.join(combo)


def generate_partial_combinations(pattern, chars):
    """Generate combinations based on a pattern where '?' represents a wildcard character"""
    if '?' not in pattern:
        yield pattern
        return

    wildcard_positions = [pos for pos, char in enumerate(pattern) if char == '?']
    fixed_parts = []
    current_pos = 0

    for pos in wildcard_positions:
        if pos > current_pos:
            fixed_parts.append((current_pos, pattern[current_pos:pos]))
        current_pos = pos + 1

    if current_pos < len(pattern):
        fixed_parts.append((current_pos, pattern[current_pos:]))

    for combo in product(chars, repeat=len(wildcard_positions)):
        result = list(pattern)
        for i, char in enumerate(combo):
            result[wildcard_positions[i]] = char
        yield ''.join(result)


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
            return True
    except Exception:
        return False


def print_current_password(hash_type, current_word):
    with print_lock:
        sys.stdout.write("\r\033[K")  # Move cursor to the beginning of the line and clear it
        sys.stdout.write(f'TYPE: {hash_type} | TRYING: {current_word}')
        sys.stdout.flush()


def compute_hash(hash_type, word):
    if hash_type == 'md5':
        return md5_hash(word)
    elif hash_type == 'sha1':
        return sha1_hash(word)
    elif hash_type == 'sha256':
        return sha256_hash(word)
    elif hash_type == 'nt':
        return nt_hash(word)
    else:
        return None


def handle_match_found(success_event, target_hash, word):
    success_event.set()
    match_found_event.set()
    with print_lock:
        print(f"\nMatch found for hash {target_hash}:{Fore.LIGHTBLUE_EX} {word}")
    return word


def apply_safety_pause(safety_pause, counter):
    if not safety_pause:
        return

    if safety_pause == 1 and counter % 699999 == 0:
        time.sleep(1.35)
    elif safety_pause == 2 and counter % 699999 == 0:
        time.sleep(2)
    elif safety_pause == 3 and counter % 199999 == 0:
        time.sleep(1.5)


def brute_force(target_hash, hash_type, chars, min_length, max_length, success_event, safety_pause=None, partial=None):
    counter = 0

    if partial:
        # Use the partial pattern to generate combinations
        combinations = generate_partial_combinations(partial, chars)
    else:
        # Use regular brute force
        combinations = generate_combinations(chars, min_length, max_length)

    for word in combinations:
        if shutdown_event.is_set() or success_event.is_set():
            return None

        print_current_password(hash_type, word)

        if hash_type in ('md5', 'sha1', 'sha256', 'nt'):
            computed_hash = compute_hash(hash_type, word)
            if computed_hash == target_hash:
                return handle_match_found(success_event, target_hash, word)
        elif hash_type == 'sha512_unix':
            if sha512_crypt.verify(word, target_hash):
                return handle_match_found(success_event, target_hash, word)
        elif hash_type == 'pkzip':
            if pkzip_crack(target_hash, word):
                return handle_match_found(success_event, target_hash, word)
        else:
            raise ValueError("Unsupported hash type")

        counter += 1
        apply_safety_pause(safety_pause, counter)

    return None


def resource_printer():
    while not shutdown_event.is_set() and not match_found_event.is_set():
        cpu, mem = resource_usage()
        with print_lock:
            print(f'\n\rCPU Usage: {cpu}%    Memory Usage: {mem}%', end='', flush=True)
            print("\033[F", end='', flush=True)
        time.sleep(1)


def resource_usage():
    cpu_percent = psutil.cpu_percent(interval=0.5)
    memory_info = psutil.virtual_memory()
    return cpu_percent, memory_info.percent


def crack_hash(target_hash, hash_type, chars, min_length, max_length, success_event, safety_pause=None, partial=None):
    global threads
    result = None

    t_printer = threading.Thread(target=resource_printer)
    t_printer.daemon = True
    t_printer.start()

    try:
        thread_results = [None] * args.threads

        for i in range(args.threads):
            t = threading.Thread(target=lambda idx=i: thread_results.__setitem__(idx, brute_force(
                target_hash, hash_type, chars, min_length, max_length, success_event, safety_pause, partial)))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        # Find the first non-None result
        for res in thread_results:
            if res is not None:
                result = res
                break

    except KeyboardInterrupt:
        print("\nInitiating graceful shutdown. Please wait...")
        shutdown_event.set()
        for t in threads:
            t.join()

    finally:
        shutdown_event.set()  # Ensure resource printer stops
        if t_printer.is_alive():
            t_printer.join(timeout=1)

    return result


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
    parser.add_argument("--partial", type=str, default=None,
                        help="Specify a partial password pattern using '?' as wildcards (e.g. 'peter????')")

    args = parser.parse_args()

    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*() -_+=?<>'
    min_length = args.length
    safety_pause = args.safety
    partial = args.partial

    # Validate partial pattern if provided
    if partial:
        if not re.match(r'^[a-zA-Z0-9!@#$%^&*() \-_+=?<>?]+$', partial):
            print("Error: Partial pattern contains invalid characters.")
            exit(1)
        print(f"Using partial pattern: {partial}")
        # Count expected combinations for informational purposes
        wildcard_count = partial.count('?')
        if wildcard_count > 0:
            possible_combinations = len(chars) ** wildcard_count
            print(f"Pattern has {wildcard_count} wildcards, resulting in approximately {possible_combinations:,} combinations to try.")

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
        result = crack_hash(target_hash, args.hash_type, chars, min_length, 22, success_event, safety_pause, partial)

        if result:
            print(f"\nPassword found: {Fore.LIGHTBLUE_EX}{result}")
        elif not shutdown_event.is_set():
            print(f"\nNo match found for hash {target_hash}.")

    except KeyboardInterrupt:
        print("\nInitiating graceful shutdown. Please wait...")
        shutdown_event.set()

        for t in threads:
            if t.is_alive():
                t.join()
