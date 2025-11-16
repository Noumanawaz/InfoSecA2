import json
import os
import socket
import sys

# Ensure project root is on sys.path for "app" package imports when run as a script
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
	sys.path.insert(0, PROJECT_ROOT)
from app.common.protocol import Hello, ServerHello, DHClient, DHServer, EncryptedMessage, LoginRequest, RegisterRequest
from app.common.utils import b64e, b64d, now_ms, rand_bytes, dict_to_bytes
from app.crypto import aes as aesmod
from app.crypto import dh as dhmod
from app.crypto import pki
from app.crypto import sign as rsamod

HOST = os.getenv("SERVER_HOST", "127.0.0.1")
PORT = int(os.getenv("SERVER_PORT", "9009"))

CA_CERT = "certs/ca.crt"
CLIENT_CERT = "certs/client.crt"
CLIENT_KEY = "certs/client.key"
EXPECTED_SERVER_CN = os.getenv("SERVER_CN", None)

def send_json(conn, obj): conn.sendall(json.dumps(obj, separators=(",", ":")).encode() + b"\n")
def recv_json(conn): 
	buf=b""
	while True:
		ch=conn.recv(4096)
		if not ch: raise ConnectionError
		buf+=ch
		if b"\n" in buf:
			line,buf=buf.split(b"\n",1)
			return json.loads(line.decode())

def do_dh_exchange(conn):
	p,g = dhmod.RFC3526_GROUP14_P, dhmod.RFC3526_GROUP14_G
	a,A = dhmod.generate_keypair(p,g)
	send_json(conn, DHClient(type="dh_client", p=p, g=g, A=A).model_dump())
	reply = DHServer(**recv_json(conn))
	K = dhmod.compute_shared_key(B=reply.B, a=a, p=p)
	return K

def main():
	ca = open(CA_CERT,"rb").read()
	ccrt = open(CLIENT_CERT,"rb").read()
	ckey = open(CLIENT_KEY,"rb").read()
	priv = rsamod.load_private_key_pem(ckey)
	with socket.socket() as s:
		s.connect((HOST,PORT))
		send_json(s, Hello(type="hello", client_cert=ccrt.decode(), nonce=b64e(rand_bytes(16))).model_dump())
		sh = ServerHello(**recv_json(s))
		pki.verify_certificate_chain(sh.server_cert.encode(), ca, EXPECTED_SERVER_CN)
		# temp DH + register then login
		Kt = do_dh_exchange(s)
		# try register (ignore failure), then login
		ivc = rand_bytes(16)
		reg = RegisterRequest(email="test@example.com", username="test", password="test").model_dump()
		send_json(s, {"type":"cred","ct": b64e(ivc + aesmod.encrypt_cbc(Kt,ivc,json.dumps(reg).encode()))})
		_ = recv_json(s)
		ivc = rand_bytes(16)
		cred = LoginRequest(username="test", password="test").model_dump()
		send_json(s, {"type":"cred","ct": b64e(ivc + aesmod.encrypt_cbc(Kt,ivc,json.dumps(cred).encode()))})
		res = recv_json(s)
		if not res.get("ok"):
			print("Auth failed.")
			return
		# Session DH
		K = do_dh_exchange(s)
		# Send one message
		seq=0
		ivm = rand_bytes(16)
		ct_b64 = b64e(ivm + aesmod.encrypt_cbc(K,ivm,b"hello"))
		ts = now_ms()
		sig = b64e(rsamod.rsa_sign_sha256(priv, dict_to_bytes({"seq":seq,"ts":ts,"ct":ct_b64})))
		send_json(s, EncryptedMessage(type="msg", seq=seq, ts=ts, ct=ct_b64, sig=sig).model_dump())
		recv_json(s)
		# Replay same message (should trigger REPLAY)
		send_json(s, EncryptedMessage(type="msg", seq=seq, ts=ts, ct=ct_b64, sig=sig).model_dump())
		print(recv_json(s))

if __name__ == "__main__":
	main()


