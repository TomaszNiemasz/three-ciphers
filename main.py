#############################################
"""
    File name: main.py
    Project name:
    Author: Tomasz Jasiński
    Python Version: 3.8
    Description:
"""

# TODO: documentation and some better menu

#############################################

import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import (
	Cipher,
	algorithms,
	modes
)


class AsymmetricCipher(object):
	pass


class SymmetricCipher(object):
	symmetric_alghorithms = {
		"AES": algorithms.AES,
		"TripleDES": algorithms.TripleDES,
		"IDEA": algorithms.IDEA
	}

	def __init__(self, alghorithm):
		self.alghorithm = alghorithm
		self.alghorithm.block_size_in_bytes = int(alghorithm.block_size / 8)
		self.alghorithm.key_size_in_bytes = int(min(alghorithm.key_sizes) / 8)

	def encrypt(self, plaintext: bytes, secret_key: bytes) -> tuple:
		padder = padding.PKCS7(self.alghorithm.block_size).padder()
		iv = os.urandom(self.alghorithm.block_size_in_bytes)
		encryptor = Cipher(self.alghorithm(secret_key), modes.CBC(iv)).encryptor()
		return (
			iv,
			encryptor.update(
				padder.update(plaintext) + padder.finalize()
			) + encryptor.finalize()
		)

	def decrypt(self, ciphertext: tuple, secret_key: bytes) -> str:
		unpadder = padding.PKCS7(self.alghorithm.block_size).unpadder()
		decryptor = Cipher(self.alghorithm(secret_key), modes.CBC(ciphertext[0])).decryptor()
		return (
				unpadder.update(
					decryptor.update(ciphertext[1]) + decryptor.finalize()
				) + unpadder.finalize()
		).decode('utf-8')


class Controller:
	@staticmethod
	def select_alghorithm():
		selectable_alghorithms = {
			i + 1: v for i, v in enumerate(SymmetricCipher.symmetric_alghorithms.keys())
		}
		print("--SELECT ALGHORITHM--")
		for i in selectable_alghorithms:
			print(f"{i}:{selectable_alghorithms[i]}")
		return SymmetricCipher.symmetric_alghorithms[
			selectable_alghorithms[
				int(input("> "))
			]
		]

	@staticmethod
	def enter_plaintext():
		return input(
			f"\nEnter a plaintext to encrypt\n>"
		).encode('utf-8')

	@staticmethod
	def enter_key(key_size):
		return input(
			f"\nEnter a secret key (long for multiple of {key_size})\n>"
		).encode('utf-8')


def main():
	while True:
		cipher = SymmetricCipher(Controller.select_alghorithm())
		entered_plaintext = Controller.enter_plaintext()
		entered_key = Controller.enter_key(cipher.alghorithm.key_size_in_bytes)

		resulting_ciphertext = cipher.encrypt(entered_plaintext, entered_key)
		print(f"\nRESULTING CIPHERTEXT:\n>>{resulting_ciphertext}\n")

		if input("Decrypt your encrypted data?(y/n): ") == "y":
			decrypted_message = cipher.decrypt(resulting_ciphertext, entered_key)
			print(f"\nDECRYPTED MESSAGE:\n>>{decrypted_message}\n")
		else:
			continue


if __name__ == '__main__':
	main()
