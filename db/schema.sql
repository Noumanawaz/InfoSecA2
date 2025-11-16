CREATE TABLE IF NOT EXISTS users (
    email VARCHAR(255),
    username VARCHAR(255) UNIQUE,
    salt VARBINARY(16),
    pwd_hash CHAR(64)
);


