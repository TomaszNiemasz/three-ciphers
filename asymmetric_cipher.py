"""
    File name: asymmetric_cipher.py
    Project name: three-ciphers
    Author: Tomasz Jasiński
    Python Version: 3.8
"""

from rsa import RSA
from dsa import DSA


class AsymmetricCipher(object):
    encryption_algorithms = {
        "RSA": RSA
    }

    auth_algorithms = {
        "RSA": RSA,
        "DSA": DSA
    }

    def __init__(self, encryption_algorithm, auth_algorithm):
        self.encryption_algorithm = encryption_algorithm
        self.auth_algorithm = auth_algorithm

    def generate_keys(self, key_size: int) -> tuple:
        private_key, public_key = self.encryption_algorithm.new_key_pair(key_size)

        if self.auth_algorithm != self.encryption_algorithm:
            signature_key, verification_key = self.auth_algorithm.new_key_pair(key_size)
        else:
            signature_key = private_key
            verification_key = public_key

        return private_key, public_key, signature_key, verification_key

    def sign(self, plaintext: str, signature_key) -> bytes:
        return self.auth_algorithm.sign(
            plaintext,
            signature_key
        )

    def verify(self, plaintext: str, signature: bytes, verification_key) -> bool:
        return self.auth_algorithm.verify(
            plaintext,
            signature,
            verification_key
        )

    def encrypt(self, plaintext: str, public_key) -> bytes:
        return self.encryption_algorithm.encrypt(
            plaintext,
            public_key
        )

    def decrypt(self, ciphertext: bytes, private_key) -> str:
        return self.encryption_algorithm.decrypt(
            ciphertext,
            private_key
        )
