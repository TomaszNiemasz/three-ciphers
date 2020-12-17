"""
    File name: main.py
    Author: Tomasz Jasiński
    Python Version: 3.8
"""

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


class UtilityClass:
	ciphers_dict = {
		"1": AES,
		"2": TripleDES,
		"3": IDEA
	}

	@staticmethod
	def new_initialization_vector(iv_size):
		return os.urandom(iv_size)

	@classmethod
	def encrypt(cls, plaintext: bytes, secret_key: bytes) -> tuple:
		initialization_vector = cls.new_initialization_vector(picked_cipher.get_block_size())
		encryptor = picked_cipher.new_encryptor(initialization_vector, secret_key)
		encrypted_message = encryptor.update(plaintext) + encryptor.finalize()
		return initialization_vector, encrypted_message

	@staticmethod
	def decrypt(ciphertext: tuple, secret_key: bytes) -> str:
		decryptor = picked_cipher.new_decryptor(ciphertext[0], secret_key)
		return (decryptor.update(ciphertext[1]) + decryptor.finalize()).decode('utf-8')

	@classmethod
	def pick_cipher(cls):
		return cls.ciphers_dict[input("\n1. Use AES\n2. Use TripleDES\n3. Use IDEA\n")]

	@staticmethod
	def enter_plaintext():
		return input(
			f"\nEnter a plaintext to encrypt (long for multiple of {picked_cipher.get_block_size()}): "
		).encode('utf-8')

	@staticmethod
	def enter_key():
		return input(
			f"\nEnter a secret key (long for multiple of {picked_cipher.get_key_size()}): "
		).encode('utf-8')


if __name__ == '__main__':
	while True:
		picked_cipher = UtilityClass.pick_cipher()
		entered_plaintext = UtilityClass.enter_plaintext()
		entered_key = UtilityClass.enter_key()

		resulting_ciphertext = UtilityClass.encrypt(entered_plaintext, entered_key)
		print(f"\n->RESULTING CIPHERTEXT: {resulting_ciphertext}\n")

		if input("Decrypt your encrypted data?(y/n): ") == "y":
			decrypted_message = UtilityClass.decrypt(resulting_ciphertext, entered_key)
			print(f"\n->DECRYPTED MESSAGE: {decrypted_message}\n")
		else:
			continue
