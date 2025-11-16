"""Classic Diffie–Hellman helpers."""

import secrets
from hashlib import sha256
from typing import Tuple

# Use a safe 2048-bit MODP group (RFC 3526 group 14)
RFC3526_GROUP14_P = int(
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
	"E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16
)
RFC3526_GROUP14_G = 2


def generate_keypair(p: int = RFC3526_GROUP14_P, g: int = RFC3526_GROUP14_G) -> Tuple[int, int]:
	"""Return (a, A) where a is private exponent, A = g^a mod p."""
	a = secrets.randbits(256)
	A = pow(g, a, p)
	return a, A


def compute_shared_key(B: int, a: int, p: int = RFC3526_GROUP14_P) -> bytes:
	"""Compute K = Trunc16(SHA256(Ks)) where Ks = B^a mod p."""
	Ks = pow(B, a, p)
	Ks_bytes = Ks.to_bytes((Ks.bit_length() + 7) // 8, "big")
	return sha256(Ks_bytes).digest()[:16]

