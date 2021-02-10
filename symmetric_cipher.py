"""
    File name: symmetric_cipher.py
    Project name: three-ciphers
    Author: Tomasz Jasiński
    Python Version: 3.8
    Description:
"""

import secrets
import string
from typing import Tuple

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes
)


class SymmetricCipher(object):
    encryption_algorithms = {
        # List of available encryption algorithms
        "AES": algorithms.AES,
        "TripleDES": algorithms.TripleDES,
        "IDEA": algorithms.IDEA
    }

    def __init__(self, encryption_algorithm):
        self.encryption_algorithm = encryption_algorithm
        self.encryption_algorithm.block_size_in_bytes = int(encryption_algorithm.block_size / 8)
        self.encryption_algorithm.key_size_in_bytes = int(min(encryption_algorithm.key_sizes) / 8)

    @staticmethod
    def random_string(string_length: int) -> str:
        """
        Generate random string with given length from ascii letters and digits tables
        """
        alphabet = string.ascii_letters + string.digits
        return (
            ''.join(
                secrets.choice(alphabet) for i in range(string_length)
            )
        )

    def encrypt(self, plaintext: str, secret_key: str) -> Tuple[str, bytes, bytes]:
        """
        Generate proper padding and initialization vector,
        then encrypt given plaintext with given secret key,
        using chosen algortihm
        """
        padder = padding.PKCS7(self.encryption_algorithm.block_size).padder()
        iv = self.random_string(self.encryption_algorithm.block_size_in_bytes).encode()
        encryptor = Cipher(
            self.encryption_algorithm(secret_key.encode()),
            modes.CBC(iv)
        ).encryptor()

        ciphertext = encryptor.update(
            padder.update(plaintext.encode()) + padder.finalize()
        ) + encryptor.finalize()

        return secret_key, iv, ciphertext

    def decrypt(self, encrypted_data: tuple, secret_key: str) -> str:
        """
        Take ciphertext and initialization vector from tuple,
        then decrypt given plaintext with given secret key,
        using chosen algortihm
        """
        unpadder = padding.PKCS7(self.encryption_algorithm.block_size).unpadder()
        iv = encrypted_data[0]
        ciphertext = encrypted_data[1]
        decryptor = Cipher(
            self.encryption_algorithm(secret_key.encode()),
            modes.CBC(iv)
        ).decryptor()

        plaintext = unpadder.update(
            decryptor.update(ciphertext) + decryptor.finalize()
        ) + unpadder.finalize()

        return plaintext.decode()
