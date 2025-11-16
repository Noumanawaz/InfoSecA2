import os
import secrets
from hashlib import sha256
from typing import Optional

import psycopg2
from psycopg2.extras import register_default_jsonb

def get_db_config() -> dict:
	# Supports either PG* or existing MYSQL_* env names
	return {
		"host": os.getenv("PGHOST", os.getenv("MYSQL_HOST", "127.0.0.1")),
		"port": int(os.getenv("PGPORT", os.getenv("MYSQL_PORT", "5432"))),
		"user": os.getenv("PGUSER", os.getenv("MYSQL_USER", "scuser")),
		"password": os.getenv("PGPASSWORD", os.getenv("MYSQL_PASSWORD", "scpass")),
		"dbname": os.getenv("PGDATABASE", os.getenv("MYSQL_DATABASE", "securechat")),
	}

def connect():
	cfg = get_db_config()
	return psycopg2.connect(
		host=cfg["host"], port=cfg["port"], user=cfg["user"],
		password=cfg["password"], dbname=cfg["dbname"]
	)

def init_schema() -> None:
	cnx = connect()
	cur = cnx.cursor()
	cur.execute("""
	CREATE TABLE IF NOT EXISTS users (
		email TEXT,
		username TEXT UNIQUE,
		salt BYTEA,
		pwd_hash CHAR(64)
	)
	""")
	cnx.commit()
	cur.close()
	cnx.close()

def salted_hash(password: str, salt: bytes) -> str:
	return sha256(salt + password.encode("utf-8")).hexdigest()

def register_user(email: str, username: str, password: str) -> bool:
	cnx = connect()
	try:
		cur = cnx.cursor()
		salt = secrets.token_bytes(16)
		pwh = salted_hash(password, salt)
		cur.execute(
			"INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
			(email, username, psycopg2.Binary(salt), pwh),
		)
		cnx.commit()
		return True
	except Exception:
		cnx.rollback()
		return False
	finally:
		try: cur.close()
		except Exception: pass
		cnx.close()

def verify_login(username: str, password: str) -> bool:
	cnx = connect()
	try:
		cur = cnx.cursor()
		cur.execute("SELECT salt, pwd_hash FROM users WHERE username=%s", (username,))
		row = cur.fetchone()
		if not row:
			return False
		salt, stored = row
		return salted_hash(password, bytes(salt)) == stored
	finally:
		try: cur.close()
		except Exception: pass
		cnx.close()

if __name__ == "__main__":
	import argparse
	parser = argparse.ArgumentParser()
	parser.add_argument("--init", action="store_true")
	args = parser.parse_args()
	if args.init:
		init_schema()
		print("Initialized schema (PostgreSQL).")