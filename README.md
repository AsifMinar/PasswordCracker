# Password Cracker

A Python-based password cracking tool designed to demonstrate various password cracking techniques, including MD5 hashing, brute force attacks, wordlist-based attacks, and rainbow table generation and lookup. This project explores password security concepts for educational purposes.


## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Limitations](#limitations)
- [Contributing](#contributing)

## Overview
This project implements a password cracker in Python to illustrate password hashing and cracking techniques. It supports MD5 hashing, brute force cracking of short passwords, wordlist-based attacks using a provided wordlist, and rainbow table generation and lookup for efficient hash cracking.

The project is intended for educational purposes to highlight the vulnerabilities of weak passwords and the importance of secure hashing practices.

## Features
- **MD5 Hashing**: Generates MD5 hashes for given passwords.
- **Brute Force Cracking**: Cracks MD5 hashes by generating all possible permutations of characters up to a specified length.
- **Wordlist Attack**: Uses a wordlist to crack MD5 hashes efficiently.
- **Rainbow Table Generation**: Creates a pre-computed table of password-hash pairs.
- **Rainbow Table Lookup**: Cracks hashes by looking up pre-computed hashes in the rainbow table.

## Requirements
- Python 3.6 or higher
- No external libraries required (uses standard library `hashlib` for MD5 hashing)

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/AsifMinar/PasswordCracker.git
   ```
2. Navigate to the project directory:
   ```bash
   cd PasswordCracker
   ```
3. Ensure the `wordlist.txt` file is present in the project directory (included in the repository).

## Usage
The main script, `passwordcracker.py`, supports multiple modes of operation. Run the script with command-line arguments to specify the mode and parameters.

### Available Commands
- **Brute Force Mode**:
  ```bash
  python passwordcracker.py brute <hash> <max_length>
  ```
  Example:
  ```bash
  python passwordcracker.py brute 7a95bf926a0333f57705aeac07a362a2 4
  ```
  Cracks the given MD5 hash by generating all possible passwords up to `max_length` characters.

- **Wordlist Mode**:
  ```bash
  python passwordcracker.py wordlist <hash> <wordlist_path>
  ```
  Example:
  ```bash
  python passwordcracker.py wordlist 2bdb742fc3d075ec6b73ea414f27819a wordlist.txt
  ```
  Cracks the given MD5 hash using the provided wordlist.

- **Generate Rainbow Table**:
  ```bash
  python passwordcracker.py generate_rainbow <wordlist_path> <output_file>
  ```
  Example:
  ```bash
  python passwordcracker.py generate_rainbow wordlist.txt rainbow_table.txt
  ```
  Generates a rainbow table from the wordlist and saves it to `output_file`.

- **Rainbow Table Lookup**:
  ```bash
  python passwordcracker.py rainbow <hash> <rainbow_table_path>
  ```
  Example:
  ```bash
  python passwordcracker.py rainbow 2bdb742fc3d075ec6b73ea414f27819a rainbow_table.txt
  ```
  Cracks the given MD5 hash by looking up the rainbow table.

### Example Hashes
- `7a95bf926a0333f57705aeac07a362a2`: A 4-character password (brute force).
- `08054846bbc9933fd0395f8be516a9f9`: A 4-character password (brute force).
- `2bdb742fc3d075ec6b73ea414f27819a`: A common password (wordlist or rainbow table).

## Project Structure
```
PasswordCracker/
│
├── passwordcracker.py  # Main Python script implementing the password cracker
├── wordlist.txt        # Sample wordlist for wordlist-based attacks
└── README.md           # Project documentation
```

- **`passwordcracker.py`**: Contains the core logic for MD5 hashing, brute force cracking, wordlist attacks, and rainbow table operations.
- **`wordlist.txt`**: A small wordlist of common passwords for testing wordlist-based attacks.
- **`README.md`**: This file, providing project documentation.

## Limitations
- Only supports MD5 hashing (as per the project requirements).
- Brute force mode is computationally expensive for passwords longer than 4-5 characters.
- Rainbow table generation can be memory-intensive for large wordlists.
- No support for salting or other hashing algorithms (e.g., SHA-256, bcrypt) in the current version.

## Contributing
Contributions are welcome! If you have suggestions for improvements or additional features (e.g., support for other hashing algorithms, multi-threading, or GPU acceleration), please:
1. Fork the repository.
2. Create a new branch for your feature.
3. Submit a pull request with a clear description of your changes.
