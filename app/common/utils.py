"""Helper utilities used across client and server."""

import base64
import os
import time
from hashlib import sha256
from typing import Any, Dict


def now_ms() -> int:
	"""Return current Unix time in milliseconds as int."""
	return int(time.time() * 1000)


def b64e(b: bytes) -> str:
	"""Base64-encode bytes to URL-safe string without newlines."""
	return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
	"""Base64-decode string to bytes."""
	return base64.b64decode(s.encode("ascii"))


def sha256_hex(data: bytes) -> str:
	"""Return SHA-256 hex digest for data."""
	return sha256(data).hexdigest()


def rand_bytes(n: int) -> bytes:
	"""Cryptographically secure random bytes."""
	return os.urandom(n)


def dict_to_bytes(obj: Dict[str, Any]) -> bytes:
	"""Stable serialization for signing/hashing: key-sorted JSON bytes."""
	# Avoid circular dep on protocol; minimal JSON without whitespace
	import json
	return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

