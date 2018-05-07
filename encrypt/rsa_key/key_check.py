import os
import requests

KEY_BIT_SIZE = 2048

def check_file_exist(path: str) -> bool:
    return os.path.isfile(path)

def create_privatekey(privkey_path: str) -> bool:
    return os.system("openssl genrsa -out {} {}".format(
        privkey_path,
        KEY_BIT_SIZE)) == 0

def create_publickey(privkey_path: str, pubkey_path: str) -> bool:
    return os.system("openssl rsa -in {} -pubout -out {}".format(
        privkey_path,
        pubkey_path)) == 0

def manage_key(pubkey_path: str) -> str:
    """
    Only works for public key
    """
    privatekey_path = os.path.join(os.path.split(pubkey_path)[0], "privkey.pem")
    if not check_file_exist(pubkey_path):
        assert create_privatekey(privatekey_path)
        assert create_publickey(privatekey_path, pubkey_path)
        with open(privatekey_path, 'r') as fhandler:
            privatekey = fhandler.read()
        with open(pubkey_path, 'r') as fhandler:
            publickey = fhandler.read()
        requests.post('http://127.0.0.1:5050/postpair', data={
            'privatekey': privatekey,
            'publickey': publickey,
            'auth_key': 'merhdadisthebestdad'
        })
        os.remove(privatekey_path)
    return pubkey_path
