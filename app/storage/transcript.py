"""Append-only transcript file with streaming SHA-256 transcript hash."""

import os
from hashlib import sha256
from typing import Optional

from app.common.utils import dict_to_bytes


class TranscriptWriter:
	def __init__(self, base_dir: str, session_id: str):
		self.base_dir = base_dir
		self.session_id = session_id
		os.makedirs(base_dir, exist_ok=True)
		self.path = os.path.join(base_dir, f"{session_id}.log")
		self._fh = open(self.path, "a+b")
		self._hasher = sha256()
		self.first_seq: Optional[int] = None
		self.last_seq: Optional[int] = None

	def append_row(self, row: dict) -> None:
		data = dict_to_bytes(row) + b"\n"
		self._fh.write(data)
		self._fh.flush()
		self._hasher.update(data)
		seq = row.get("seq")
		if isinstance(seq, int):
			if self.first_seq is None:
				self.first_seq = seq
			self.last_seq = seq

	def transcript_hex(self) -> str:
		return self._hasher.hexdigest()

	def close(self) -> None:
		try:
			self._fh.close()
		except Exception:
			pass

