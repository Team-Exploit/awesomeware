import os
import sys
import json

from base64 import b64encode, b64decode

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization, asymmetric, hashes
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding

BLOCK_SIZE = 16
IV_SIZE = BLOCK_SIZE
KEY_SIZE = BLOCK_SIZE * 2

RSA_PUBLICKEY_FILEPATH = "../rsa/pubkey.pem"
RSA_PRIVATEKEY_FILEPATH = "../rsa/mykey.pem"

def bytes_to_str(data: bytes) -> str:
    return b64encode(data).decode('utf-8')

def str_to_bytes(data: str) -> bytes:
    return b64decode(data.encode('utf-8'))

def to_bits(byte_size: int) -> int:
    return byte_size * 8

def generate_iv() -> bytes:
    return os.urandom(IV_SIZE)

def generate_key() -> bytes:
    return os.urandom(KEY_SIZE)

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
    key = generate_key()
    ext = os.path.splitext(filepath)[1]
    with open(filepath, 'rb') as binary:
        data = binary.read()
    if len(data) % BLOCK_SIZE:
        padder = padding.PKCS7(to_bits(BLOCK_SIZE)).padder()
        padded_data = padder.update(data) + padder.finalize()
        data = padded_data
    ciphertext, iv = my_encrypt(data, key)
    return ciphertext, iv, key, ext

def my_file_decrypt(filepath: str, key: bytes, iv: bytes) -> tuple:
    with open(filepath, 'rb') as binary:
        data = binary.read()
    plaintext = my_decrypt(data, key, iv)
    unpadder = padding.PKCS7(to_bits(BLOCK_SIZE)).unpadder()
    unpadded_plaintext = unpadder.update(plaintext) + unpadder.finalize()
    return unpadded_plaintext

def my_rsa_encrypt(filepath: str) -> tuple:
    """
    In this method,
    you first call MyfileEncrypt(filepath) which will return (C, IV, key, ext).
    You then will initialize an RSA public key encryption object
    and load pem publickey from the RSA_publickey_filepath.
    Lastly, you encrypt the key variable ("key") using the RSA publickey in OAEP padding mode.
    The result will be RSACipher.
    You then return (RSACipher, C, IV, ext). 
    """
    ciphertext, iv, key, ext = my_file_encrypt(filepath)
    with open(RSA_PUBLICKEY_FILEPATH, 'rb') as pem_file:
        public_key = serialization.load_pem_public_key(
            pem_file.read(),
            backend=default_backend())
    rsa_cipher = public_key.encrypt(
        key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))
    return (rsa_cipher, ciphertext, iv, ext)

def my_rsa_decrypt(rsa_cipher, ciphertext, iv, ext: str, rsa_privatekey_filepath: str) -> tuple:
    """
    Remember to do the inverse
    MyRSADecrypt (RSACipher, C, IV, ext, RSA_Privatekey_filepath)
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

def main():
    if len(sys.argv) > 1:
        my_file = sys.argv[1]
    else:
        print('Usage: $> python encrypt.py <file>')
        return
    rsa_cipher, ciphertext, iv, ext = my_rsa_encrypt(my_file)
    data = {
        'iv':  bytes_to_str(iv),
        'rsa_cipher': bytes_to_str(rsa_cipher),
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
    assert 'iv' in json_data and 'rsa_cipher' in json_data and 'ext' in json_data
    data2 = {
        'iv': str_to_bytes(json_data['iv']),
        'rsa_cipher': str_to_bytes(json_data['rsa_cipher']),
        'ext': json_data['ext']
    }
    plaintext = my_rsa_decrypt(
        data2['rsa_cipher'],
        'data/encrypted',
        data2['iv'],
        data2['ext'],
        RSA_PRIVATEKEY_FILEPATH)
    with open('data/decryted{}'.format(data2['ext']), 'wb') as not_so_secret_data:
        not_so_secret_data.write(plaintext)
    print("Decryption done")

if __name__ == "__main__":
    main()
