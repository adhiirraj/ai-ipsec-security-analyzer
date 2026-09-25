"""Replaceable file encryption backend.

Contract: encrypt(data, key) -> (ciphertext, JSON-serializable parameters)
          decrypt(ciphertext, key, parameters) -> plaintext
The key is 32 bytes derived independently for each file.
"""
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ALGORITHM = 'AES-256-CTR'


def encrypt(data: bytes, key: bytes):
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    ctx = cipher.encryptor()
    return ctx.update(data) + ctx.finalize(), {'nonce': nonce.hex()}


def decrypt(ciphertext: bytes, key: bytes, parameters: dict):
    nonce = bytes.fromhex(parameters['nonce'])
    if len(nonce) != 16:
        raise ValueError('Invalid AES-CTR nonce')
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    ctx = cipher.decryptor()
    return ctx.update(ciphertext) + ctx.finalize()
