"""AES-128-CBC with PKCS#7 padding using cryptography library."""

from typing import Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

BLOCK_SIZE_BYTES = 16


def _get_cipher(key: bytes, iv: bytes) -> Cipher:
	if len(key) != 16:
		raise ValueError("AES-128 requires 16-byte key")
	if len(iv) != 16:
		raise ValueError("AES-CBC requires 16-byte IV")
	return Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())


def pkcs7_pad(data: bytes) -> bytes:
	padder = padding.PKCS7(BLOCK_SIZE_BYTES * 8).padder()
	return padder.update(data) + padder.finalize()


def pkcs7_unpad(padded: bytes) -> bytes:
	unpadder = padding.PKCS7(BLOCK_SIZE_BYTES * 8).unpadder()
	return unpadder.update(padded) + unpadder.finalize()


def encrypt_cbc(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
	cipher = _get_cipher(key, iv)
	encryptor = cipher.encryptor()
	return encryptor.update(pkcs7_pad(plaintext)) + encryptor.finalize()


def decrypt_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
	cipher = _get_cipher(key, iv)
	decryptor = cipher.decryptor()
	plain_padded = decryptor.update(ciphertext) + decryptor.finalize()
	return pkcs7_unpad(plain_padded)

