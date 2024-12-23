# File Encryption

A python script for encrypting and decrypting files run over the command line.
The script uses AES encryption.
It creates a unique key and initialization vector for each file and further encrypts them.

## Table of contents

- [File Encryption](#file-encryption)
  - [Table of contents](#table-of-contents)
  - [Built With](#built-with)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)

## Built With

- [Python 3.8](https://www.python.org/) - The programming language used.
- [Cryptography](https://cryptography.io/en/latest/) - The cryptography library used.

## Prerequisites

What things you need to install the software and how to install them

- **python 3**

Linux:

```sh
sudo apt-get install python3.8
```

Windows:

Download from [python.org](https://www.python.org/downloads/windows/)

Mac OS:

```sh
brew install python3
```

- **pip**

Linux and Mac OS:

```sh
pip install -U pip
```

Windows:

```sh
python -m pip install -U pip
```

## Installation

To set up virtual environment and install dependencies:

```sh
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

To encrypt a file:

```sh
python encryption.py -e filepath/filename
```

To decrypt a file:

```sh
python encryption.py -d filepath/filename
```

To access help menu:

```sh
python encryption.py -h
```

For more info on how to run command line scripts in Laravel:
[How to execute an external/linux/windows commands in laravel 5](https://www.phpflow.com/php/how-to-execute-an-external-linux-windows-commands-in-laravel-5/)
