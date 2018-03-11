import os
import sys
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

def my_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> tuple:
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
    return plaintext

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

def my_file_decrypt(filepath: str, key: bytes, iv: bytes) -> tuple:
    with open(filepath, 'rb') as binary:
        data = binary.read()
    plaintext = my_decrypt(data, key, iv)
    unpadder = padding.PKCS7(to_bit(BLOCK_SIZE)).unpadder()
    unpadded_plaintext = unpadder.update(plaintext) + unpadder.finalize()
    plaintext = unpadded_plaintext
    return plaintext

def main():
    if len(sys.argv) > 1:
        my_file = sys.argv[1]
    else:
        print('Usage: $> python encrypt.py <file>')
        return
    ciphertext, iv, key, ext = my_file_encrypt(my_file)
    data = {
        'iv':  bytes_to_str(iv),
        'key': bytes_to_str(key),
        'ext': ext
    }
    with open('data/encrypted', 'wb') as secret_data:
        secret_data.write(ciphertext)
    with open('data/data.json', 'w') as json_file:
        json.dump(data, json_file)
    print("Encryption done")    
    with open('data/data.json', 'r') as json_file:
        json_raw = json_file.read()
        json_data = json.loads(json_raw)
    data2 = {
        'iv': b64decode(json_data['iv'].encode('utf-8')),
        'key': b64decode(json_data['key'].encode('utf-8')),
        'ext': json_data['ext']
    }
    plaintext = my_file_decrypt('data/encrypted', data2['key'], data2['iv'])
    with open('data/decryted{}'.format(data2['ext']), 'wb') as not_so_secret_data:
        not_so_secret_data.write(plaintext)
    print("Decryption done")

if __name__ == "__main__":
    main()
