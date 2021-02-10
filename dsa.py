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
    @staticmethod
    def new_key_pair(key_size: int):
        private_key = dsa.generate_private_key(
            key_size=key_size
        )
        public_key = private_key.public_key()

        return private_key, public_key

    @staticmethod
    def sign(plaintext: str, private_key) -> bytes:
        signature = private_key.sign(
            plaintext.encode(),
            hashes.SHA256()
        )
        return signature

    @staticmethod
    def verify(plaintext: str, signature: bytes, public_key) -> bool:
        try:
            public_key.verify(
                signature,
                plaintext.encode(),
                hashes.SHA256()
            )
            return True

        except InvalidSignature:
            return False
