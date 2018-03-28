import os
import json

from base64 import b64decode

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization, asymmetric, hashes
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding

BLOCK_SIZE = 16
IV_SIZE = BLOCK_SIZE
KEY_SIZE = BLOCK_SIZE * 2

RSA_PRIVATEKEY_FILEPATH = "../rsa/mykey.pem"

def to_bits(byte_size: int) -> int:
    return byte_size * 8

def str_to_bytes(data: str) -> bytes:
    return b64decode(data.encode('utf-8'))

def my_aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> tuple:
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

def my_file_decrypt(filepath: str, key: bytes, iv: bytes) -> tuple:
    with open(filepath, 'rb') as binary:
        data = binary.read()
    plaintext = my_aes_decrypt(data, key, iv)
    unpadder = padding.PKCS7(to_bits(BLOCK_SIZE)).unpadder()
    unpadded_plaintext = unpadder.update(plaintext) + unpadder.finalize()
    return unpadded_plaintext

def my_rsa_decrypt(rsa_cipher, ciphertext, iv, ext: str, rsa_privatekey_filepath: str) -> tuple:
    """
    which does the exactly inverse of the above
    and generate the decrypted file using your previous decryption methods.
    """
    with open(rsa_privatekey_filepath, 'rb') as pem_file:
        private_key = serialization.load_pem_private_key(
            pem_file.read(),
            password=None,
            backend=default_backend())
    key = private_key.decrypt(
        rsa_cipher,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))
    return my_file_decrypt(ciphertext, key, iv)

def my_decrypt(input_path: str, output_path: str, json_path:str, is_folder: bool):
    with open(json_path, 'r') as json_fh:
        json_raw = json_fh.read()
        json_data = json.loads(json_raw)
    assert 'iv' in json_data and 'rsa_cipher' in json_data and 'ext' in json_data
    data = {
        'iv': str_to_bytes(json_data['iv']),
        'rsa_cipher': str_to_bytes(json_data['rsa_cipher']),
        'ext': json_data['ext']
    }
    plaintext = my_rsa_decrypt(
        data['rsa_cipher'],
        input_path,
        data['iv'],
        data['ext'],
        RSA_PRIVATEKEY_FILEPATH)
    with open('{}{}'.format(output_path, data['ext']), 'wb') as output_fh:
        output_fh.write(plaintext)
