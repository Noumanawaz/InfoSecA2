"""Threaded secure chat server (application-layer crypto, no TLS)."""

import json
import os
import socket
import threading
import time
from typing import Tuple

from app.common.protocol import (
	Hello, ServerHello, DHClient, DHServer, EncryptedMessage, SessionReceipt, RegisterRequest, LoginRequest
)
from app.common.utils import b64e, b64d, now_ms, rand_bytes, dict_to_bytes, sha256_hex
from app.crypto import aes as aesmod
from app.crypto import dh as dhmod
from app.crypto import pki
from app.crypto import sign as rsamod
from app.storage.db import verify_login, register_user
from app.storage.transcript import TranscriptWriter


HOST = os.getenv("SERVER_HOST", "127.0.0.1")
PORT = int(os.getenv("SERVER_PORT", "9009"))
CA_CERT_PATH = os.getenv("CA_CERT", "certs/ca.crt")
SERVER_CERT_PATH = os.getenv("SERVER_CERT", "certs/server.crt")
SERVER_KEY_PATH = os.getenv("SERVER_KEY", "certs/server.key")
EXPECTED_CLIENT_CN = os.getenv("CLIENT_CN", None)
EXPECTED_SERVER_CN = os.getenv("SERVER_CN", None)  # for self-checks/logging
TIME_SKEW_MS = int(os.getenv("TIME_SKEW_MS", "300000"))  # 5 minutes


def load_server_materials():
	with open(CA_CERT_PATH, "rb") as f:
		ca_pem = f.read()
	with open(SERVER_CERT_PATH, "rb") as f:
		server_cert_pem = f.read()
	with open(SERVER_KEY_PATH, "rb") as f:
		server_key_pem = f.read()
	server_priv = rsamod.load_private_key_pem(server_key_pem)
	server_cert = pki.load_cert(server_cert_pem)
	return ca_pem, server_cert_pem, server_priv, server_cert


def send_json(conn: socket.socket, obj: dict) -> None:
	data = json.dumps(obj, separators=(",", ":")).encode("utf-8") + b"\n"
	conn.sendall(data)


def recv_json(conn: socket.socket) -> dict:
	buf = b""
	while True:
		chunk = conn.recv(4096)
		if not chunk:
			raise ConnectionError("connection closed")
		buf += chunk
		if b"\n" in buf:
			line, buf = buf.split(b"\n", 1)
			return json.loads(line.decode("utf-8"))


def derive_sig_input(seq: int, ts: int, ct_b64: str) -> bytes:
	return dict_to_bytes({"seq": seq, "ts": ts, "ct": ct_b64})


def do_dh_exchange(conn: socket.socket) -> Tuple[bytes, bytes]:
	"""Perform a DH exchange. Returns (key, iv)."""
	msg = DHClient(**recv_json(conn))
	a, A = dhmod.generate_keypair(msg.p, msg.g)
	send_json(conn, DHServer(type="dh_server", B=pow(msg.g, a, msg.p)).dict())
	K = dhmod.compute_shared_key(B=msg.A, a=a, p=msg.p)
	iv = rand_bytes(16)
	return K, iv


def handle_client(conn: socket.socket, addr):
	ca_pem, server_cert_pem, server_priv, server_cert = load_server_materials()
	tw = TranscriptWriter(base_dir="transcripts", session_id=f"{int(time.time())}-{addr[0]}-{addr[1]}")
	session_started = False
	try:
		# Phase 1: Hello / ServerHello
		cli_hello = Hello(**recv_json(conn))
		# Validate client certificate
		pki.verify_certificate_chain(cli_hello.client_cert.encode("utf-8"), ca_pem, EXPECTED_CLIENT_CN)

		s_nonce = rand_bytes(16)
		send_json(conn, ServerHello(type="server_hello", server_cert=server_cert_pem.decode("utf-8"), nonce=b64e(s_nonce)).model_dump())

		# Temporary DH for credential exchange (DH-1)
		tmp_key, tmp_iv = do_dh_exchange(conn)

		# Receive credentials encrypted with tmp AES
		enc_obj = recv_json(conn)
		if enc_obj.get("type") != "cred":
			raise ValueError("expected credential envelope")
		ct_full = b64d(enc_obj["ct"])
		iv_cred, ct = ct_full[:16], ct_full[16:]
		pt = aesmod.decrypt_cbc(tmp_key, iv_cred, ct)
		cred = json.loads(pt.decode("utf-8"))
		action = cred.get("type")
		ok = False
		if action == "register":
			req = RegisterRequest(**cred)
			ok = register_user(req.email, req.username, req.password)
		elif action == "login":
			req = LoginRequest(**cred)
			ok = verify_login(req.username, req.password)
		else:
			raise ValueError("unknown credential message")
		send_json(conn, {"type": "cred_result", "ok": ok})
		if not ok:
			return

		# Phase 2: DH Session Key
		K, iv = do_dh_exchange(conn)
		session_started = True

		client_cert = pki.load_cert(cli_hello.client_cert.encode("utf-8"))
		client_pub = client_cert.public_key()

		seq_expected = 0
		alive = True
		while alive:
			obj = EncryptedMessage(**recv_json(conn))
			# Anti-replay: seq check
			if obj.seq != seq_expected:
				send_json(conn, {"type": "error", "code": "REPLAY"})
				break
			seq_expected += 1
			# Timestamp freshness
			if abs(now_ms() - obj.ts) > TIME_SKEW_MS:
				send_json(conn, {"type": "error", "code": "STALE"})
				break
			# Verify signature
			sig_input = derive_sig_input(obj.seq, obj.ts, obj.ct)
			if not rsamod.rsa_verify_sha256(client_pub, b64d(obj.sig), sig_input):
				send_json(conn, {"type": "error", "code": "SIG_FAIL"})
				break
			# Decrypt (ct = iv || ciphertext)
			ct_full = b64d(obj.ct)
			iv_msg, ct_only = ct_full[:16], ct_full[16:]
			plaintext = aesmod.decrypt_cbc(K, iv_msg, ct_only)
			# Console visibility
			try:
				print(f"[C2S] {addr[0]}:{addr[1]} seq={obj.seq} ts={obj.ts} msg={plaintext.decode('utf-8')}")
			except Exception:
				print(f"[C2S] {addr[0]}:{addr[1]} seq={obj.seq} ts={obj.ts} (non-utf8 payload)")
			# Append to transcript
			tw.append_row({"dir": "C2S", "seq": obj.seq, "ts": obj.ts, "ct": obj.ct, "pt": plaintext.decode("utf-8")})

			# Echo back broadcast (single-client server for assignment scope)
			iv_reply = rand_bytes(16)
			reply_ct = iv_reply + aesmod.encrypt_cbc(K, iv_reply, plaintext)
			reply_seq = obj.seq  # mirror
			reply_ts = now_ms()
			reply_ct_b64 = b64e(reply_ct)
			reply_sig = b64e(rsamod.rsa_sign_sha256(server_priv, derive_sig_input(reply_seq, reply_ts, reply_ct_b64)))
			send_json(conn, EncryptedMessage(type="msg", seq=reply_seq, ts=reply_ts, ct=reply_ct_b64, sig=reply_sig).model_dump())
			tw.append_row({"dir": "S2C", "seq": reply_seq, "ts": reply_ts, "ct": reply_ct_b64})
			try:
				print(f"[S2C] seq={reply_seq} ts={reply_ts} msg={plaintext.decode('utf-8')}")
			except Exception:
				print(f"[S2C] seq={reply_seq} ts={reply_ts} (non-utf8 payload)")

	except Exception:
		# Best-effort receipt on error or close
		pass
	finally:
		# Non-repudiation: Session receipt signed by server
		try:
			if session_started:
				trans_hex = tw.transcript_hex()
				first_seq = tw.first_seq if tw.first_seq is not None else 0
				last_seq = tw.last_seq if tw.last_seq is not None else -1
				receipt_body = {
					"type": "receipt",
					"transcript_sha256": trans_hex,
					"first_seq": first_seq,
					"last_seq": last_seq,
				}
				receipt_sig = rsamod.rsa_sign_sha256(server_priv, dict_to_bytes(receipt_body))
				receipt = SessionReceipt(**{**receipt_body, "sig": b64e(receipt_sig)}).model_dump()
				try:
					send_json(conn, receipt)
				except Exception:
					pass
		finally:
			tw.close()
			try:
				conn.close()
			except Exception:
				pass


def main():
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.bind((HOST, PORT))
		s.listen()
		print(f"Server listening on {HOST}:{PORT}")
		while True:
			conn, addr = s.accept()
			t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
			t.start()


if __name__ == "__main__":
	main()
