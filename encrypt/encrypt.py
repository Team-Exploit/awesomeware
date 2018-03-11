import os
import json
from base64 import b64encode, b64decode

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

BLOCK_SIZE = 16
IV_SIZE = BLOCK_SIZE

def bytes_to_str(data: bytes) -> str:
    return b64encode(data).decode('utf-8')

def to_bit(byte_size: int) -> int:
    return byte_size * 8

def generate_iv() -> bytes:
    return os.urandom(IV_SIZE)

def generate_key() -> bytes:
    return os.urandom(BLOCK_SIZE * 2)

def my_encrypt(message: bytes, key: bytes, **kwargs) -> tuple:
    """
    Encrypt bytes using a 32B key and a 16B initialisation vector IV
    If the IV is not provided, one will be generated
    args:
        message: str
        key: str
    kwargs:
        iv: bytes
    return: (ciphertext:str, IV: str)
    """
    iv = generate_iv()
    encrypt = Cipher(
        algorithm=algorithms.AES(key),
        mode=modes.CBC(iv),
        backend=default_backend()).encryptor()
    ciphertext = encrypt.update(message) + encrypt.finalize()
    return ciphertext, iv

def my_decrypt(ciphertext, key, iv) -> tuple:
    """
    Decrypt a ciphertext
    args:
        ciphertext: bytes
        key: bytes
        iv: bytes
    """
    decrypt = Cipher(
        algorithm=algorithms.AES(key),
        mode=modes.CBC(iv),
        backend=default_backend()).decryptor()
    plaintext = decrypt.update(ciphertext) + decrypt.finalize()
    return plaintext, iv

def my_file_encrypt(filepath: str) -> tuple:
    """
    Encrypt a file at the given path
    args:
        filepath: str
    """
    key = os.urandom(BLOCK_SIZE * 2)
    ext = os.path.splitext(filepath)[1]
    with open(filepath, 'rb') as binary:
        data = binary.read()
    if len(data) % BLOCK_SIZE:
        padder = padding.PKCS7(to_bit(BLOCK_SIZE)).padder()
        padded_data = padder.update(data) + padder.finalize()
        data = padded_data
    ciphertext, iv = my_encrypt(data, key)
    return ciphertext, iv, key, ext

def my_file_decrypt(filepath: str) -> tuple:
    ## TODO
    plaintext = ""
    iv = ""
    key = ""
    ext = ""
    return plaintext, iv, key, ext

def main():
    ciphertext, iv, key, ext = my_file_encrypt('encrypt/data/article.txt')
    data = {
        'iv':  bytes_to_str(iv),
        'key': bytes_to_str(key),
        'ext': ext
    }
    with open('encrypt/data/encrypted.txt', 'wb') as secret_data:
        secret_data.write(ciphertext)
    with open('encrypt/data/data.json', 'w') as json_file:
        json.dump(data, json_file)
    print("Encryption done")
    pass

if __name__ == "__main__":
    main()
