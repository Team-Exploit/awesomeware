import os
import json

from base64 import b64encode

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization, asymmetric, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding

BLOCK_SIZE = 16 #bytes
IV_SIZE = BLOCK_SIZE
KEY_SIZE = BLOCK_SIZE * 2

RSA_PUBLICKEY_FILEPATH = "../rsa/pubkey.pem"

SHA256_DIGEST_SIZE = 256 #bits

def to_bits(byte_size: int) -> int:
    return byte_size * 8

def bytes_to_str(data: bytes) -> str:
    return b64encode(data).decode('utf-8')

def generate_iv() -> bytes:
    return os.urandom(IV_SIZE)

def generate_key() -> bytes:
    return os.urandom(KEY_SIZE)

def my_aes_encrypt(message: bytes, key: bytes, **kwargs) -> tuple:
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

def my_file_encrypt(filepath: str) -> tuple:
    """
    Encrypt a file at the given path
    args:
        filepath: str
    """
    key = generate_key()
    ext = os.path.splitext(filepath)[1]
    with open(filepath, 'rb') as binary:
        data = binary.read()
    if len(data) % BLOCK_SIZE:
        padder = padding.PKCS7(to_bits(BLOCK_SIZE)).padder()
        padded_data = padder.update(data) + padder.finalize()
        data = padded_data
    ciphertext, iv = my_aes_encrypt(data, key)
    return ciphertext, iv, key, ext

def rsa_publickey_encrypt(message: bytes, rsa_pubkey_filepath: str = RSA_PUBLICKEY_FILEPATH) -> bytes:
    with open(rsa_pubkey_filepath, 'rb') as pem_file:
        public_key = serialization.load_pem_public_key(
            pem_file.read(),
            backend=default_backend())
    rsa_cipher = public_key.encrypt(
        message,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))
    return rsa_cipher

def my_encrypt_mac(plaintext: bytes, enc_key: bytes, hmac_key: bytes) -> tuple:
    iv = generate_iv()
    encrypt = Cipher(
        algorithm=algorithms.AES(enc_key),
        mode=modes.CBC(iv),
        backend=default_backend()).encryptor()
    ciphertext = encrypt.update(plaintext) + encrypt.finalize()
    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    tag = h.finalize()
    return ciphertext, iv, tag

def my_file_encrypt_mac(filepath: str) -> tuple:
    enc_key = generate_key()
    hmac_key = generate_key()
    ext = os.path.splitext(filepath)[1]
    with open(filepath, 'rb') as binary:
        data = binary.read()
    if len(data) % BLOCK_SIZE:
        padder = padding.PKCS7(to_bits(BLOCK_SIZE)).padder()
        padded_data = padder.update(data) + padder.finalize()
        data = padded_data
    ciphertext, iv, tag = my_encrypt_mac(data, enc_key, hmac_key)
    return ciphertext, iv, tag, enc_key, hmac_key, ext

# def my_rsa_encrypt(filepath: str) -> tuple:
#     """
#     you first call MyfileEncrypt(filepath) which will return (C, IV, key, ext).
#     You then will initialize an RSA public key encryption object
#     and load pem publickey from the RSA_publickey_filepath.
#     Lastly, you encrypt the key variable ("key") using the RSA publickey in OAEP padding mode.
#     The result will be RSACipher.
#     You then return (RSACipher, C, IV, ext). 
#     """
#     ciphertext, iv, key, ext = my_file_encrypt(filepath)
#     rsa_cipher = rsa_publickey_encrypt(key)
#     return (rsa_cipher, ciphertext, iv, ext)

def my_rsa_encrypt(filepath, rsa_pubkey_filepath: str = RSA_PUBLICKEY_FILEPATH) -> tuple:
    ciphertext, iv, tag, enc_key, hmac_key, ext = my_file_encrypt_mac(filepath)
    rsa_cipher = rsa_publickey_encrypt(enc_key + hmac_key, rsa_pubkey_filepath)
    return rsa_cipher, ciphertext, iv, tag, ext

def my_encrypt(input_path: str, output_path: str, json_path: str, is_folder: bool) -> None:
    rsa_cipher, ciphertext, iv, tag, ext = my_rsa_encrypt(input_path)
    data = {
        'iv':  bytes_to_str(iv),
        'rsa_cipher': bytes_to_str(rsa_cipher),
        'tag': bytes_to_str(tag),
        'ext': ext
    }
    with open(output_path, 'wb') as output_fh:
        output_fh.write(ciphertext)
    with open(json_path, 'w') as json_fh:
        json.dump(data, json_fh)
