"""Console client for Secure Chat (application-layer crypto, no TLS)."""

import json
import os
import socket
import sys
from typing import Tuple

from app.common.protocol import Hello, ServerHello, DHClient, DHServer, EncryptedMessage, SessionReceipt, RegisterRequest, LoginRequest
from app.common.utils import b64e, b64d, now_ms, rand_bytes, dict_to_bytes
from app.crypto import aes as aesmod
from app.crypto import dh as dhmod
from app.crypto import pki
from app.crypto import sign as rsamod


HOST = os.getenv("SERVER_HOST", "127.0.0.1")
PORT = int(os.getenv("SERVER_PORT", "9009"))
CA_CERT_PATH = os.getenv("CA_CERT", "certs/ca.crt")
CLIENT_CERT_PATH = os.getenv("CLIENT_CERT", "certs/client.crt")
CLIENT_KEY_PATH = os.getenv("CLIENT_KEY", "certs/client.key")
EXPECTED_SERVER_CN = os.getenv("SERVER_CN", None)
TIME_SKEW_MS = int(os.getenv("TIME_SKEW_MS", "300000"))  # 5 minutes


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
	"""Perform a DH exchange. Returns (key, iv placeholder not used further)."""
	p, g = dhmod.RFC3526_GROUP14_P, dhmod.RFC3526_GROUP14_G
	a, A = dhmod.generate_keypair(p, g)
	send_json(conn, DHClient(type="dh_client", p=p, g=g, A=A).model_dump())
	reply = DHServer(**recv_json(conn))
	K = dhmod.compute_shared_key(B=reply.B, a=a, p=p)
	iv = rand_bytes(16)
	return K, iv


def main():
	with open(CA_CERT_PATH, "rb") as f:
		ca_pem = f.read()
	with open(CLIENT_CERT_PATH, "rb") as f:
		client_cert_pem = f.read()
	with open(CLIENT_KEY_PATH, "rb") as f:
		client_key_pem = f.read()
	client_priv = rsamod.load_private_key_pem(client_key_pem)
	client_cert = pki.load_cert(client_cert_pem)

	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.connect((HOST, PORT))

		# Phase 1: Hello
		c_nonce = rand_bytes(16)
		send_json(s, Hello(type="hello", client_cert=client_cert_pem.decode("utf-8"), nonce=b64e(c_nonce)).model_dump())
		srv_hello = ServerHello(**recv_json(s))

		# Validate server certificate
		pki.verify_certificate_chain(srv_hello.server_cert.encode("utf-8"), ca_pem, EXPECTED_SERVER_CN)

		# Temporary DH for credential exchange (DH-1)
		tmp_key, tmp_iv = do_dh_exchange(s)

		# Registration or login
		print("Choose: [1] Register  [2] Login")
		choice = input("> ").strip()
		if choice == "1":
			email = input("Email: ").strip()
			username = input("Username: ").strip()
			password = input("Password: ").strip()
			cred = RegisterRequest(email=email, username=username, password=password).model_dump()
		else:
			username = input("Username: ").strip()
			password = input("Password: ").strip()
			cred = LoginRequest(username=username, password=password).model_dump()
		ivc = rand_bytes(16)
		ct = aesmod.encrypt_cbc(tmp_key, ivc, json.dumps(cred, separators=(",", ":")).encode("utf-8"))
		send_json(s, {"type": "cred", "ct": b64e(ivc + ct)})
		res = recv_json(s)
		if not res.get("ok"):
			print("Authentication failed.")
			return
		print("Authentication OK.")

		# Phase 2: DH Session Key
		K, iv = do_dh_exchange(s)
		server_cert = pki.load_cert(srv_hello.server_cert.encode("utf-8"))
		server_pub = server_cert.public_key()

		seq = 0
		print("Enter messages; Ctrl+C or empty line to quit.")
		try:
			while True:
				plaintext = input("> ")
				if plaintext is None or plaintext == "":
					break
				ivm = rand_bytes(16)
				ct = ivm + aesmod.encrypt_cbc(K, ivm, plaintext.encode("utf-8"))
				ts = now_ms()
				ct_b64 = b64e(ct)
				sig = b64e(rsamod.rsa_sign_sha256(client_priv, derive_sig_input(seq, ts, ct_b64)))
				send_json(s, EncryptedMessage(type="msg", seq=seq, ts=ts, ct=ct_b64, sig=sig).model_dump())
				seq += 1
				# Receive server reply
				reply = EncryptedMessage(**recv_json(s))
				# Verify
				if abs(now_ms() - reply.ts) > TIME_SKEW_MS:
					print("[WARN] Stale server message")
				if not rsamod.rsa_verify_sha256(server_pub, b64d(reply.sig), derive_sig_input(reply.seq, reply.ts, reply.ct)):
					print("[ERROR] Invalid server signature")
					break
				pt = aesmod.decrypt_cbc(K, iv, b64d(reply.ct))
				print(f"[server] {pt.decode('utf-8')}")
		except KeyboardInterrupt:
			pass
		finally:
			# Expect a receipt
			try:
				obj = recv_json(s)
				if obj.get("type") == "receipt":
					rec = SessionReceipt(**obj)
					# Verify server signature on receipt hash
					body = {
						"type": "receipt",
						"transcript_sha256": rec.transcript_sha256,
						"first_seq": rec.first_seq,
						"last_seq": rec.last_seq,
					}
					ok = rsamod.rsa_verify_sha256(server_pub, b64d(rec.sig), dict_to_bytes(body))
					path = os.path.join("transcripts", f"receipt-{int(now_ms())}.json")
					os.makedirs("transcripts", exist_ok=True)
					with open(path, "w") as f:
						json.dump({**body, "sig": rec.sig, "verified": ok}, f)
					print(f"Saved receipt to {path} (verified={ok})")
			except Exception:
				pass


if __name__ == "__main__":
	main()
