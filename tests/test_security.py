import time

import pyotp

from app.core.security import (decrypt_text, encrypt_text, hash_password, new_opaque_token, sha256_hex,
                               verify_password, verify_totp)


def test_password_hash():
    h = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", h) and not verify_password("nope", h)


def test_totp_accepts_and_blocks_replay():
    secret = pyotp.random_base32()
    code = pyotp.TOTP(secret).now()
    step = verify_totp(secret, code, None)
    assert step is not None
    assert verify_totp(secret, code, step) is None                     # replay del mismo código
    nxt = pyotp.TOTP(secret).at(int(time.time()) + 30)
    assert verify_totp(secret, nxt, step) == step + 1                  # el siguiente sí
    assert verify_totp(secret, "000000", None) is None and verify_totp(secret, "abc", None) is None


def test_encryption_and_opaque_tokens():
    assert decrypt_text(encrypt_text("evidencia")) == "evidencia" and encrypt_text("a") != "a"
    raw, h = new_opaque_token()
    assert sha256_hex(raw) == h and raw != h
