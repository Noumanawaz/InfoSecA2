"""X.509 validation helpers: CA-signed, validity window, CN/SAN checks."""

from datetime import datetime, timezone
from typing import Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption


def load_cert(pem_bytes: bytes) -> x509.Certificate:
	return x509.load_pem_x509_certificate(pem_bytes)


def verify_cert_signed_by(cert: x509.Certificate, issuer_cert: x509.Certificate) -> bool:
	issuer_pubkey = issuer_cert.public_key()
	issuer_pubkey.verify(
		cert.signature,
		cert.tbs_certificate_bytes,
		padding.PKCS1v15(),
		cert.signature_hash_algorithm,
	)
	return True


def check_validity_window(cert: x509.Certificate) -> bool:
	now = datetime.now(timezone.utc)
	# Use UTC properties to avoid deprecation warnings
	if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
		raise ValueError("Certificate not within validity window")
	return True


def get_common_name(cert: x509.Certificate) -> Optional[str]:
	try:
		attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
		if attrs:
			return attrs[0].value
	except Exception:
		return None
	return None


def has_san_dns(cert: x509.Certificate, dns: str) -> bool:
	try:
		ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
		return dns in ext.value.get_values_for_type(x509.DNSName)
	except x509.ExtensionNotFound:
		return False


def verify_certificate_chain(cert_pem: bytes, ca_pem: bytes, expected_cn: Optional[str] = None) -> None:
	"""Raises on failure; returns None on success."""
	cert = load_cert(cert_pem)
	ca = load_cert(ca_pem)
	# Signature by CA
	verify_cert_signed_by(cert, ca)
	# Validity window
	check_validity_window(cert)
	# CN or SAN check if expected provided
	if expected_cn:
		cn = get_common_name(cert)
		if cn != expected_cn and not has_san_dns(cert, expected_cn):
			raise ValueError("Certificate CN/SAN mismatch")

