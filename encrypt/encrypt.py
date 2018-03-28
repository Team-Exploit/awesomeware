import os
import sys
import json
import argparse

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

def encrypt(input_path: str, output_path: str, json_path: str, is_folder: bool):
    rsa_cipher, ciphertext, iv, ext = my_rsa_encrypt(input_path)
    data = {
        'iv':  bytes_to_str(iv),
        'rsa_cipher': bytes_to_str(rsa_cipher),
        'ext': ext
    }
    with open(output_path, 'wb') as output_fh:
        output_fh.write(ciphertext)
    with open(json_path, 'w') as json_fh:
        json.dump(data, json_fh)

def decrypt(input_path: str, output_path: str, json_path:str, is_folder: bool):
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

def main():
    parser = argparse.ArgumentParser(
        prog="encrypt.py",
        description="Peform encryption/decryption operations")
    ## args.input
    parser.add_argument(
        'input',
        type=str,
        help='Input file')
    ## args.decrypt
    parser.add_argument(
        '-d', '--decrypt',
        action='store_true',
        help="Set the program in decryption mode")
    ## args.output
    parser.add_argument(
        '-o', '--out', '--output',
        type=str,
        action='store',
        metavar="output_file",
        default="output",
        dest="output",
        help="Spectify the name of the output file")
    ## args.json
    parser.add_argument(
        '-j', '--json',
        type=str,
        action='store',
        metavar="json_file",
        default="data.json",
        help="Specify the json file to read/write encryption data")
    ## args.folder
    parser.add_argument(
        '-F', '--folder',
        action='store_true',
        help="Specify that the target is a folder")
    args = parser.parse_args(sys.argv[1:])
    if args.decrypt:
        decrypt(args.input, args.output, args.json, args.folder)
    else:
        encrypt(args.input, args.output, args.json, args.folder)

if __name__ == "__main__":
    main()
