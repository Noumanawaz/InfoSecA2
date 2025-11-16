## SecureChat – End-to-End Secure Console Chat (CIANR)

This project implements a complete console-based secure chat system with application-layer cryptography only (no TLS/SSL). It provides:

- Confidentiality: AES-128-CBC
- Integrity: SHA-256
- Authentication: X.509 CA + RSA + password login
- Non-repudiation: Append-only transcript + signed session receipt
- Key agreement: Classic Diffie–Hellman
- Database: MySQL for user registration and login (salted SHA-256)

### Tech Summary

- App-layer protocol over plain TCP sockets
- Certificates: custom CA, server, and client certs
- crypto: `cryptography` (AES, RSA, X.509), classic DH
- DB: `mysql-connector-python`

---

## Setup

1. Python env

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

2. MySQL (Docker suggested)

```bash
docker run -d --name securechat-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat \
  -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass \
  -p 3306:3306 mysql:8
```

3. Create schema

```bash
python -m app.storage.db --init
```

Schema also available at `db/schema.sql`.

4. Generate certificates

```bash
python scripts/gen_ca.py --name "Local Root CA"
python scripts/gen_cert.py --cn server.local --out certs/server
python scripts/gen_cert.py --cn client.local --out certs/client
```

This writes:

- `certs/ca.key`, `certs/ca.crt`
- `certs/server.key`, `certs/server.crt`
- `certs/client.key`, `certs/client.crt`

5. Environment variables (optional)

- `SERVER_HOST` (default `127.0.0.1`)
- `SERVER_PORT` (default `9009`)
- `CA_CERT` (default `certs/ca.crt`)
- `SERVER_CERT`, `SERVER_KEY`
- `CLIENT_CERT`, `CLIENT_KEY`
- `SERVER_CN`, `CLIENT_CN` (for CN checks)
- `MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_USER`, `MYSQL_PASSWORD`, `MYSQL_DATABASE`

---

## Run

Server:

```bash
python -m app.server
```

Client (new terminal):

```bash
python -m app.client
```

Client will prompt to register or login. Credentials are protected using a temporary DH-derived AES key during Phase 1. Chat uses a new DH-derived AES session key (Phase 2).

Transcripts and receipts are written under `transcripts/`.

---

## Protocol (implemented)

Phase 1 — Control Plane

- Client → Server: `hello` with client cert PEM and 16-byte nonce (b64)
- Server → Client: `server_hello` with server cert PEM and 16-byte nonce (b64)
- Both validate certificates against CA and CN/SAN. Then run DH-1 to derive a temporary AES key for credential exchange (`register` or `login`).

Phase 2 — DH Session Key

- Client → Server: `dh_client` {p,g,A}
- Server → Client: `dh_server` {B}
- Ks = B^a mod p; K = SHA256(Ks)[:16] used as AES-128 key

Phase 3 — Encrypted Messaging

```
{ "type":"msg", "seq":n, "ts":unix_ms,
  "ct": base64(AES128-CBC(plaintext)),
  "sig": base64(RSA_SIGN_SHA256(seq||ts||ct))
}
```

Both sides verify signature, sequence number monotonicity, and timestamp freshness. Decrypt, print, and append to transcript.

Phase 4 — Non-Repudiation

- On session end, server computes `TranscriptHash=SHA256(all rows)`
- Sends:

```
{ "type":"receipt", "transcript_sha256":"<hex>",
  "first_seq":..., "last_seq":..., "sig":base64(RSA_SIGN(TranscriptHash)) }
```

- Client stores receipt in `transcripts/` and verifies signature.

---

## Tests

Small utilities under `tests/`:

- `tests/replay.py` — performs login and sends the same message twice; server responds with `{"type":"error","code":"REPLAY"}`.
- `tests/tamper.py` — signs one ciphertext but sends another; server responds with `{"type":"error","code":"SIG_FAIL"}`.
- `tests/bad_cert.py` — sends a bogus certificate in `hello`; server should close or error (invalid certificate).

Usage examples (with running server and a created test user):

```bash
python tests/replay.py
python tests/tamper.py
python tests/bad_cert.py
```

To create a test user, start client and choose Register.

---

## Wireshark Capture

Capture loopback `lo0` (macOS) or `Loopback`/`Any`:

- Filter: `tcp.port == 9009`
- You should see JSON frames but ciphertext fields `ct` are not intelligible.
- Include screenshots in your report.

---

## Notes

- No TLS/SSL is used; all crypto is at application layer.
- Passwords are stored as salted SHA-256 in MySQL.
- Certificate validation includes CA signature, validity window, and CN/SAN check.
