"""Issue end-entity RSA cert signed by Root CA (SAN=DNSName(CN))."""

import os
import argparse
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def load_ca(ca_key_path: str, ca_crt_path: str):
	with open(ca_key_path, "rb") as f:
		ca_key = serialization.load_pem_private_key(f.read(), password=None)
	with open(ca_crt_path, "rb") as f:
		ca_cert = x509.load_pem_x509_certificate(f.read())
	return ca_key, ca_cert


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("--cn", required=True, help="Common Name (and SAN DNSName)")
	parser.add_argument("--out", required=True, help="Output prefix directory (e.g., certs/server)")
	parser.add_argument("--ca-dir", default="certs", help="Directory containing ca.key and ca.crt")
	args = parser.parse_args()

	ca_key_path = os.path.join(args.ca_dir, "ca.key")
	ca_crt_path = os.path.join(args.ca_dir, "ca.crt")
	ca_key, ca_cert = load_ca(ca_key_path, ca_crt_path)

	outdir = os.path.dirname(args.out) if os.path.splitext(args.out)[1] else args.out
	os.makedirs(outdir, exist_ok=True)

	# Generate key
	key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

	subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, args.cn)])
	now = datetime.now(timezone.utc)
	csr = (
		x509.CertificateSigningRequestBuilder()
		.subject_name(subject)
		.add_extension(x509.SubjectAlternativeName([x509.DNSName(args.cn)]), critical=False)
		.sign(key, hashes.SHA256())
	)

	cert = (
		x509.CertificateBuilder()
		.subject_name(csr.subject)
		.issuer_name(ca_cert.subject)
		.public_key(key.public_key())
		.serial_number(x509.random_serial_number())
		.not_valid_before(now - timedelta(days=1))
		.not_valid_after(now + timedelta(days=3650))
		.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
		.add_extension(x509.SubjectAlternativeName([x509.DNSName(args.cn)]), critical=False)
		.sign(private_key=ca_key, algorithm=hashes.SHA256())
	)

	key_path = f"{args.out}.key" if os.path.splitext(args.out)[1] == "" else args.out.replace(".crt", ".key")
	crt_path = f"{args.out}.crt" if os.path.splitext(args.out)[1] == "" else args.out.replace(".key", ".crt")
	# Normalize for provided examples: if out='certs/server' -> certs/server.key, certs/server.crt
	if key_path.endswith(".crt"):
		key_path = key_path[:-4] + ".key"
	if crt_path.endswith(".key"):
		crt_path = crt_path[:-4] + ".crt"

	with open(key_path, "wb") as f:
		f.write(
			key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption(),
			)
		)
	with open(crt_path, "wb") as f:
		f.write(cert.public_bytes(serialization.Encoding.PEM))

	print(f"Wrote {key_path} and {crt_path}")


if __name__ == "__main__":
	main()

