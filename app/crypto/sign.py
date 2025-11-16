"""RSA PKCS#1 v1.5 SHA-256 sign/verify helpers and PEM loaders."""

from typing import Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend


def load_private_key_pem(pem_data: bytes, password: Optional[bytes] = None):
	return serialization.load_pem_private_key(pem_data, password=password, backend=default_backend())


def load_public_key_pem(pem_data: bytes):
	return serialization.load_pem_public_key(pem_data, backend=default_backend())


def rsa_sign_sha256(private_key, data: bytes) -> bytes:
	return private_key.sign(
		data,
		padding.PKCS1v15(),
		hashes.SHA256(),
	)


def rsa_verify_sha256(public_key, signature: bytes, data: bytes) -> bool:
	from cryptography.exceptions import InvalidSignature
	try:
		public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
		return True
	except InvalidSignature:
		return False

