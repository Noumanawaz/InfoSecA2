"""Pydantic models and simple schema helpers for the wire protocol."""

from typing import Optional, Literal
from pydantic import BaseModel, Field, validator


class Hello(BaseModel):
	type: Literal["hello"] = "hello"
	client_cert: str
	nonce: str = Field(description="base64-encoded 16 random bytes")


class ServerHello(BaseModel):
	type: Literal["server_hello"] = "server_hello"
	server_cert: str
	nonce: str = Field(description="base64-encoded 16 random bytes")


class RegisterRequest(BaseModel):
	type: Literal["register"] = "register"
	email: str
	username: str
	password: str


class LoginRequest(BaseModel):
	type: Literal["login"] = "login"
	username: str
	password: str


class DHClient(BaseModel):
	type: Literal["dh_client"] = "dh_client"
	p: int
	g: int
	A: int

	@validator("p", "g", "A")
	def positive(cls, v: int) -> int:
		if v <= 0:
			raise ValueError("DH parameter must be positive")
		return v


class DHServer(BaseModel):
	type: Literal["dh_server"] = "dh_server"
	B: int

	@validator("B")
	def positive(cls, v: int) -> int:
		if v <= 0:
			raise ValueError("DH parameter must be positive")
		return v


class EncryptedMessage(BaseModel):
	type: Literal["msg"] = "msg"
	seq: int
	ts: int
	ct: str  # base64 ciphertext
	sig: str # base64 signature over SHA256(seq||ts||ct)

	@validator("seq")
	def non_negative_seq(cls, v: int) -> int:
		if v < 0:
			raise ValueError("seq must be non-negative")
		return v


class SessionReceipt(BaseModel):
	type: Literal["receipt"] = "receipt"
	transcript_sha256: str # hex string
	first_seq: int
	last_seq: int
	sig: str # base64 signature on transcript hash

