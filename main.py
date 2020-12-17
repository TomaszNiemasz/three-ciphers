import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class TripleDES:

    @staticmethod
    def new_encryptor(initialization_vector, secret_key):
        return Cipher(
            algorithms.TripleDES(secret_key),
            modes.CBC(initialization_vector)
        ).encryptor()

    @staticmethod
    def new_decryptor(initialization_vector, secret_key):
        return Cipher(
            algorithms.TripleDES(secret_key),
            modes.CBC(initialization_vector)
        ).decryptor()

    @staticmethod
    def get_block_size():
        return int(algorithms.TripleDES.block_size / 8)

    @staticmethod
    def get_key_size():
        return int(min(algorithms.TripleDES.key_sizes) / 8)


class IDEA:

    @staticmethod
    def new_encryptor(initialization_vector, secret_key):
        return Cipher(
            algorithms.IDEA(secret_key),
            modes.CBC(initialization_vector)
        ).encryptor()

    @staticmethod
    def new_decryptor(initialization_vector, secret_key):
        return Cipher(
            algorithms.IDEA(secret_key),
            modes.CBC(initialization_vector)
        ).decryptor()

    @staticmethod
    def get_block_size():
        return int(algorithms.IDEA.block_size / 8)

    @staticmethod
    def get_key_size():
        return int(min(algorithms.IDEA.key_sizes) / 8)


class AES:

    @staticmethod
    def new_encryptor(initialization_vector, secret_key):
        return Cipher(
            algorithms.AES(secret_key),
            modes.CBC(initialization_vector)
        ).encryptor()

    @staticmethod
    def new_decryptor(initialization_vector, secret_key):
        return Cipher(
            algorithms.AES(secret_key),
            modes.CBC(initialization_vector)
        ).decryptor()

    @staticmethod
    def get_block_size():
        return int(algorithms.AES.block_size / 8)

    @staticmethod
    def get_key_size():
        return int(min(algorithms.AES.key_sizes) / 8)


ciphers_dictionary = {
    "1": AES,
    "2": TripleDES,
    "3": IDEA
}


def new_initialization_vector(iv_size):
    return os.urandom(iv_size)


def encrypt(plaintext: bytes, secret_key: bytes) -> tuple:
    initialization_vector = new_initialization_vector(picked_cipher.get_block_size())
    encryptor = picked_cipher.new_encryptor(initialization_vector, secret_key)
    encrypted_message = encryptor.update(plaintext) + encryptor.finalize()
    return initialization_vector, encrypted_message


def decrypt(ciphertext: tuple, secret_key: bytes) -> str:
    decryptor = picked_cipher.new_decryptor(ciphertext[0], secret_key)
    return (decryptor.update(ciphertext[1]) + decryptor.finalize()).decode('utf-8')


def pick_cipher():
    return ciphers_dictionary[input("\n1. Use AES\n2. Use TripleDES\n3. Use IDEA\n")]


def enter_plaintext():
    return input(
        f"\nEnter a plaintext to encrypt (long for multiple of {picked_cipher.get_block_size()}): "
    ).encode('utf-8')


def enter_key():
    return input(
        f"\nEnter a secret key (long for multiple of {picked_cipher.get_key_size()}): "
    ).encode('utf-8')


if __name__ == '__main__':

    while True:
        picked_cipher = pick_cipher()
        entered_plaintext = enter_plaintext()
        entered_key = enter_key()

        resulting_ciphertext = encrypt(entered_plaintext, entered_key)
        print(f"->CIPHERTEXT: {resulting_ciphertext}\n")

        if input("Decrypt your encrypted data?(y/n): ") == "y":
            decrypted_message = decrypt(resulting_ciphertext, entered_key)
            print(f"->DECRYPTED MESSAGE: {decrypted_message}\n")
        else:
            continue
