"""Create Root CA (RSA 2048 + self-signed X.509)."""

import os
import argparse
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography import x509


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("--name", required=True, help="Common Name for Root CA")
	parser.add_argument("--outdir", default="certs", help="Directory to write ca.key and ca.crt")
	args = parser.parse_args()

	os.makedirs(args.outdir, exist_ok=True)

	# Generate private key
	key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

	subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, args.name)])
	now = datetime.now(timezone.utc)
	cert = (
		x509.CertificateBuilder()
		.subject_name(subject)
		.issuer_name(issuer)
		.public_key(key.public_key())
		.serial_number(x509.random_serial_number())
		.not_valid_before(now - timedelta(days=1))
		.not_valid_after(now + timedelta(days=3650))
		.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
		.add_extension(x509.KeyUsage(
			key_cert_sign=True, crl_sign=True,
			digital_signature=False, content_commitment=False,
			key_encipherment=False, data_encipherment=False,
			key_agreement=False, encipher_only=False, decipher_only=False
		), critical=True)
		.sign(private_key=key, algorithm=hashes.SHA256())
	)

	key_path = os.path.join(args.outdir, "ca.key")
	cert_path = os.path.join(args.outdir, "ca.crt")
	with open(key_path, "wb") as f:
		f.write(
			key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption(),
			)
		)
	with open(cert_path, "wb") as f:
		f.write(cert.public_bytes(serialization.Encoding.PEM))

	print(f"Wrote {key_path} and {cert_path}")


if __name__ == "__main__":
	main()

