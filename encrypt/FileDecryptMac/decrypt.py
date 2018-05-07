import os
import json

from base64 import b64decode
import requests

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization, asymmetric, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding

BLOCK_SIZE = 16
IV_SIZE = BLOCK_SIZE
KEY_SIZE = BLOCK_SIZE * 2

RSA_PUBLICKEY_FILEPATH = "../rsa/pubkey.pem"
RSA_PRIVATEKEY_FILEPATH = "../rsa/privkey.pem"

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

# def my_rsa_decrypt(rsa_cipher, ciphertext, iv, ext: str, rsa_privatekey_filepath: str) -> tuple:
#     with open(rsa_privatekey_filepath, 'rb') as pem_file:
#         private_key = serialization.load_pem_private_key(
#             pem_file.read(),
#             password=None,
#             backend=default_backend())
#     key = private_key.decrypt(
#         rsa_cipher,
#         rsa_padding.OAEP(
#             mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None))
#     return my_file_decrypt(ciphertext, key, iv)

def rsa_privkey_decrypt(rsa_cipher: bytes, rsa_privkey_filepath: str = RSA_PRIVATEKEY_FILEPATH) -> bytes:
    with open(rsa_privkey_filepath, 'rb') as pem_file:
        private_key = serialization.load_pem_private_key(
            pem_file.read(),
            password=None,
            backend=default_backend())
    message = private_key.decrypt(
        rsa_cipher,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))
    return message

def my_decrypt_hmac(ciphertext: bytes, enc_key: bytes, hmac_key: bytes, iv: bytes, tag: bytes) -> tuple:
    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    h.verify(tag)
    decrypt = Cipher(
        algorithm=algorithms.AES(enc_key),
        mode=modes.CBC(iv),
        backend=default_backend()).decryptor()
    plaintext = decrypt.update(ciphertext) + decrypt.finalize()
    return plaintext

def my_file_decrypt_mac(ciphertext: bytes, enc_key: bytes, hmac_key: bytes, iv: bytes, tag: bytes) -> tuple:
    plaintext = my_decrypt_hmac(ciphertext, enc_key, hmac_key, iv, tag)
    unpadder = padding.PKCS7(to_bits(BLOCK_SIZE)).unpadder()
    unpadded_plaintext = unpadder.update(plaintext) + unpadder.finalize()
    return unpadded_plaintext
    
def my_rsa_decrypt(rsa_cipher, ciphertext: bytes, iv, ext: str, tag: bytes, rsa_privkey_filepath: str) -> tuple:
    key = rsa_privkey_decrypt(rsa_cipher, rsa_privkey_filepath)
    enc_key = key[:KEY_SIZE]
    hmac_key = key[KEY_SIZE:]
    plaintext = my_file_decrypt_mac(ciphertext, enc_key, hmac_key, iv, tag)
    return plaintext

def my_decrypt(input_path: str):
    with open(input_path, 'r') as json_fh:
        json_raw = json_fh.read()
        json_data = json.loads(json_raw)
    # assert 'iv' in json_data and 'rsa_cipher' in json_data and 'ext' in json_data
    data = {
        'iv': str_to_bytes(json_data['IV']),
        'rsa_cipher': str_to_bytes(json_data['RSACipher']),
        'ext': json_data['ext'],
        'tag': str_to_bytes(json_data['tag']),
        'C': str_to_bytes(json_data['C'])
    }

    if not os.path.exists(RSA_PUBLICKEY_FILEPATH):
        raise KeyError('No publickey found')
    with open(RSA_PUBLICKEY_FILEPATH, 'r') as fhandler:
        pubkey = fhandler.read()
    resp = requests.get('http://127.0.0.1:5050/getprivatekey', params={
        'auth_key': 'merhdadisthebestdad',
        'publickey': pubkey
    })
    print(resp)
    jresp = resp.json()
    if jresp['status'] != 'ok':
        raise KeyError('Status not ok')
    with open(RSA_PRIVATEKEY_FILEPATH, 'w') as fhandler:
        fhandler.write(jresp['privatekey'])
    plaintext = my_rsa_decrypt(
        data['rsa_cipher'],
        data['C'],
        data['iv'],
        data['ext'],
        data['tag'],
        RSA_PRIVATEKEY_FILEPATH)
    name, _ = os.path.splitext(input_path)
    output_path = '{}{}'.format(name, data['ext'])
    with open(output_path, 'wb') as output_fh:
        output_fh.write(plaintext)
    os.remove(RSA_PRIVATEKEY_FILEPATH)
