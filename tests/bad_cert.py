import json
import os
import socket
import sys

# Ensure project root is on sys.path for "app" package imports when run as a script
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
	sys.path.insert(0, PROJECT_ROOT)

from app.common.protocol import Hello
from app.common.utils import b64e, rand_bytes

HOST = os.getenv("SERVER_HOST", "127.0.0.1")
PORT = int(os.getenv("SERVER_PORT", "9009"))

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

def main():
	# Send a bogus self-signed cert blob; server should reject after hello
	bad_cert_pem = "-----BEGIN CERTIFICATE-----\nMIIBbadCERT==\n-----END CERTIFICATE-----\n"
	with socket.socket() as s:
		s.connect((HOST,PORT))
		send_json(s, Hello(type="hello", client_cert=bad_cert_pem, nonce=b64e(rand_bytes(16))).model_dump())
		# Depending on implementation, server may close or error on next read
		try:
			print(recv_json(s))
		except Exception as e:
			print("Server closed connection (BAD_CERT).")

if __name__ == "__main__":
	main()


