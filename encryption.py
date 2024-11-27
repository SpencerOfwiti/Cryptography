# standard imports
import argparse
import enum
import gc
import logging
import os
from base64 import b64encode, b64decode
from typing import Tuple

# third party imports
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# run garbage collection
gc.collect()

# setup logging
logging.basicConfig(level=logging.DEBUG)
logg = logging.getLogger()

# define command line arguments
arg_parser = argparse.ArgumentParser(description='perform encryption or decryption on a file')
group = arg_parser.add_mutually_exclusive_group()
group.add_argument('-d', '--decrypt', action='store_true', help='perform decryption')
group.add_argument('-e', '--encrypt', action='store_true', help='perform encryption')
arg_parser.add_argument('file', type=str, help='file to be manipulated')
args = arg_parser.parse_args()


# Enum for size units
class SizeUnit(enum.Enum):
    BYTES = 1
    KB = 2
    MB = 3
    GB = 4


def convert_unit(size_in_bytes: int, unit: SizeUnit) -> float:
    """
    Convert the size from bytes to other units like KB, MB or GB.
    :param size_in_bytes: The file size in bytes.
    :type size_in_bytes: int
    :param unit: The size unit to be converted to.
    :type unit: SizeUnit
    :return: The file size in the unit requested.
    :rtype: float
    """
    if unit == SizeUnit.KB:
        return size_in_bytes / 1024
    elif unit == SizeUnit.MB:
        return size_in_bytes / (1024 * 1024)
    elif unit == SizeUnit.GB:
        return size_in_bytes / (1024 * 1024 * 1024)
    else:
        return size_in_bytes


def get_file_size(file_name: str, size_type: SizeUnit = SizeUnit.BYTES) -> float:
    """
    Get file in size in given unit like KB, MB or GB.
    :param file_name: The location and name of file to be analysed.
    :type file_name: str
    :param size_type: The size unit to be converted to.
    :type size_type: SizeUnit
    :return: The file size in the unit requested.
    :rtype: float
    """
    size = os.path.getsize(file_name)
    return convert_unit(size, size_type)


def key_search(key_name: str) -> bool:
    """
    This function is used to get the availability of an encryption key and initialization vector.
    :param key_name: The name of the file the encryption key and initialization vector is stored in.
    :type key_name: str
    :return: Whether the key and initialization vector are available or not
    :rtype: bool
    """
    key_file = f'keys/{key_name}.key'
    iv_file = f'ivs/{key_name}.iv'
    if os.path.exists(key_file) and os.path.exists(iv_file) and os.path.isfile(key_file) and os.path.isfile(
            iv_file):
        return True

    return False


class Encryptor:
    """This class is used to perform encryption and decryption of data items."""
    with open('keys/master_key.key') as key:
        _master_key = b64decode(key.read())
    with open('ivs/master_iv.iv') as iv:
        _master_iv = b64decode(iv.read())
    _master_cipher = Cipher(algorithm=algorithms.AES(_master_key), mode=modes.CBC(_master_iv))

    def key_write(self, key_name: str) -> Tuple[bytes, bytes]:
        """
        This function is used to create and store an encryption key and initialization vector in the file system.
        :param key_name: The name of the file to be stored in.
        :type key_name: str
        :return: The generated key and initialization vector.
        :rtype: tuple
        """
        new_key = os.urandom(32)
        new_iv = os.urandom(16)
        encryptor = self._master_cipher.encryptor()
        encrypted_key = encryptor.update(new_key)
        encrypted_iv = encryptor.update(new_iv) + encryptor.finalize()

        with open(f'keys/{key_name}.key', 'wb') as mykey:
            mykey.write(b64encode(encrypted_key))

        with open(f'ivs/{key_name}.iv', 'wb') as myiv:
            myiv.write(b64encode(encrypted_iv))

        return new_key, new_iv

    def key_load(self, key_name: str) -> Tuple[bytes, bytes]:
        """
        This function is used to load an encryption key and initialization vector from the a file.
        :param key_name: The name of the file the variables are stored in.
        :type key_name: tuple
        :return: The stored key and initialization vector.
        :rtype: tuple
        """
        with open(f'keys/{key_name}.key', 'rb') as mykey:
            key = b64decode(mykey.read())

        with open(f'ivs/{key_name}.iv', 'rb') as myiv:
            iv = b64decode(myiv.read())

        decryptor = self._master_cipher.decryptor()
        decrypted_key = decryptor.update(key)
        decrypted_iv = decryptor.update(iv) + decryptor.finalize()

        return decrypted_key, decrypted_iv

    def file_encrypt(self, file_path: str):
        """
        This function is used to encrypt files.
        :param file_path: The location and name of file to be encrypted.
        :type file_path: str
        """
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            logg.error('File not found!')
            return

        initial_size = get_file_size(file_path, SizeUnit.MB)
        logg.info(f'Initial file size: {initial_size} MB.')
        logg.info('Starting encryption...')

        file_name = os.path.normpath(file_path).split(os.path.sep)[-1]
        if key_search(file_name):
            key, iv = self.key_load(file_name)
        else:
            key, iv = self.key_write(file_name)

        cipher = Cipher(algorithm=algorithms.AES(key), mode=modes.CBC(iv))
        encryptor = cipher.encryptor()

        with open(file_path, 'rb') as file:
            original = file.read()

        # add padding to match block size
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(original) + padder.finalize()

        encrypted = encryptor.update(padded_data) + encryptor.finalize()

        with open(file_path, 'wb') as file:
            file.write(encrypted)

        logg.info('Concluding encryption...')
        final_size = get_file_size(file_path, SizeUnit.MB)
        logg.info(f'Final file size: {final_size} MB.')

    def file_decrypt(self, file_path: str):
        """
        This function is used to decrypt files.
        :param file_path: The location and name of the file to be decrypted.
        :type file_path: str
        """
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            logg.error('File not found!')
            return

        initial_size = get_file_size(file_path, SizeUnit.MB)
        logg.info(f'Initial file size: {initial_size} MB.')
        logg.info('Starting decryption...')

        file_name = os.path.normpath(file_path).split(os.path.sep)[-1]
        if not key_search(file_name):
            logg.error('Encryption key for file not found!')
            return

        key, iv = self.key_load(file_name)

        cipher = Cipher(algorithm=algorithms.AES(key), mode=modes.CBC(iv))
        decryptor = cipher.decryptor()

        with open(file_path, 'rb') as file:
            encrypted = file.read()

        decrypted = decryptor.update(encrypted) + decryptor.finalize()

        # remove padding to match original file
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted) + unpadder.finalize()

        with open(file_path, 'wb') as file:
            file.write(unpadded_data)

        logg.info('Concluding decryption...')
        final_size = get_file_size(file_path, SizeUnit.MB)
        logg.info(f'Final file size: {final_size} MB.')


arg_file = args.file
cryptographic_engine = Encryptor()

if args.encrypt:
    # encrypt a file
    cryptographic_engine.file_encrypt(arg_file)
elif args.decrypt:
    # decrypt a file
    cryptographic_engine.file_decrypt(arg_file)
