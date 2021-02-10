"""
    File name: dsa.py
    Project name: three-ciphers
    Author: Tomasz Jasiński
    Python Version: 3.8
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    dsa
)


class DSA:
    key_sizes = [
        # List of available key sizes
        1024,
        2048,
        3072,
        4096
    ]

    @staticmethod
    def new_key_pair(key_size: int):
        """
        Generate new key pair
        """
        private_key = dsa.generate_private_key(
            key_size=key_size
        )
        public_key = private_key.public_key()

        return private_key, public_key

    @staticmethod
    def sign(plaintext: str, private_key) -> bytes:
        """
        Create digital signature from given message and signature key,
        using additional hashing function
        """
        signature = private_key.sign(
            plaintext.encode(),
            hashes.SHA256()
        )
        return signature

    @staticmethod
    def verify(plaintext: str, signature: bytes, public_key) -> bool:
        """
        Authenticate given message with given signature and verification key,
        using additional hashing function
        """
        try:
            public_key.verify(
                signature,
                plaintext.encode(),
                hashes.SHA256()
            )
            return True

        except InvalidSignature:
            return False
