"""Password-based encryption for exported reports (AES-256-GCM)."""

from __future__ import annotations

import os

MAGIC = b"TGCTCRY1"
SALT_LEN = 16
NONCE_LEN = 12
ITERATIONS = 200_000


class CryptoUnavailable(RuntimeError):
    pass


def _aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
    except Exception as exc:  # noqa: BLE001
        raise CryptoUnavailable("缺少 cryptography 依赖，无法加密报告") from exc
    return AESGCM, PBKDF2HMAC, hashes


def _key(password: str, salt: bytes):
    AESGCM, PBKDF2HMAC, hashes = _aesgcm()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(data: bytes, password: str) -> bytes:
    if not password:
        raise ValueError("密码不能为空")
    AESGCM, _, _ = _aesgcm()
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(_key(password, salt)).encrypt(nonce, data, MAGIC)
    return MAGIC + salt + nonce + ciphertext


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    if not blob.startswith(MAGIC):
        raise ValueError("不是本软件的加密报告")
    body = blob[len(MAGIC) :]
    if len(body) < SALT_LEN + NONCE_LEN + 16:
        raise ValueError("加密报告已损坏")
    salt = body[:SALT_LEN]
    nonce = body[SALT_LEN : SALT_LEN + NONCE_LEN]
    ciphertext = body[SALT_LEN + NONCE_LEN :]
    AESGCM, _, _ = _aesgcm()
    return AESGCM(_key(password, salt)).decrypt(nonce, ciphertext, MAGIC)
