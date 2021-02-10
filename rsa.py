"""
    File name: rsa.py
    Project name: three-ciphers
    Author: Tomasz Jasiński
    Python Version: 3.8
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    padding
)


class RSA:
    key_sizes = [
        1024,
        2048,
        4096
    ]

    @staticmethod
    def new_key_pair(key_size: int):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        public_key = private_key.public_key()

        return private_key, public_key

    @staticmethod
    def sign(plaintext: str, private_key) -> bytes:
        signature = private_key.sign(
            plaintext.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    @staticmethod
    def verify(plaintext: str, signature: bytes, public_key) -> bool:
        try:
            public_key.verify(
                signature,
                plaintext.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True

        except InvalidSignature:
            return False

    @staticmethod
    def encrypt(plaintext: str, public_key) -> bytes:
        ciphertext = public_key.encrypt(
            plaintext.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    @staticmethod
    def decrypt(ciphertext: bytes, private_key) -> str:
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()
