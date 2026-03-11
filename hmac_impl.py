#!/usr/bin/env python3
"""HMAC — Hash-based Message Authentication Code (RFC 2104)."""
import hashlib, sys

def hmac(key, message, hash_func=hashlib.sha256):
    block_size = 64
    if len(key) > block_size: key = hash_func(key).digest()
    key = key.ljust(block_size, b'\x00')
    o_key_pad = bytes(k ^ 0x5c for k in key)
    i_key_pad = bytes(k ^ 0x36 for k in key)
    inner = hash_func(i_key_pad + message).digest()
    return hash_func(o_key_pad + inner).hexdigest()

def hmac_verify(key, message, expected, hash_func=hashlib.sha256):
    computed = hmac(key, message, hash_func)
    # Constant-time comparison
    if len(computed) != len(expected): return False
    result = 0
    for a, b in zip(computed, expected): result |= ord(a) ^ ord(b)
    return result == 0

if __name__ == "__main__":
    key = b"secret-key"
    msg = b"Hello, HMAC!"
    tag = hmac(key, msg)
    print(f"HMAC-SHA256: {tag}")
    print(f"Verify: {hmac_verify(key, msg, tag)}")
    print(f"Tamper: {hmac_verify(key, msg + b'!', tag)}")
    # SHA-1 variant
    tag1 = hmac(key, msg, hashlib.sha1)
    print(f"HMAC-SHA1:   {tag1}")
