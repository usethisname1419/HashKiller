## HashKiller by Derek Johnston

Welcome to HashKiller, an efficient and user-friendly tool designed to brute-force specific hash types from a provided file.

# Description

HashKiller is designed to help security enthusiasts, researchers, and developers test the strength of passwords by attempting to brute-force their way through a given hash. With support for multiple hashing algorithms and additional safety features, HashKiller provides a versatile platform for hash cracking.

# Features

  Supports various hashing algorithms:
        MD5
        SHA-1
        SHA-256
        SHA-512 (UNIX)
        Windows NT

  Multi-threaded brute-forcing: Use up to 4 threads for faster hash cracking.

  Safety throttle: Prevents CPU from being overused by introducing controlled pauses.

  Color-coded results: Easily distinguish between cracked and uncracked hashes.


# Installation

To install HashKiller and make it directly callable from the terminal:

Clone the Repository:


`git clone https://github.com/your_github_username/HashKiller.git
cd HashKiller`

Replace your_github_username with the appropriate GitHub username.

Run the Installation Script:
First, ensure the script is executable:

`chmod +x install.sh`

Then, execute the script:

`./install.sh`

After a successful installation, you can call HashKiller directly from any terminal window using the HashKiller command.

# Usage

`$python hashkiller.py --hash YOUR_HASH_FILE --hash-type HASH_TYPE [--length PASSWORD_MIN_LENGTH] [--threads NUM_OF_THREADS] [--safety]`

Replace placeholders (YOUR_HASH_FILE, HASH_TYPE, etc.) with appropriate values.
Donations

If you found HashKiller useful and would like to show appreciation, consider donating:

BTC:
    `bc1qd3se09vq3wp63tfq5fgcpcmvy8ef7r09z8h5kd`

ETH:
    `0xB139a7f6A2398fd4F50BbaC9970da8BE57E6F539`

Your support is greatly appreciated!
