import os

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
    if not check_file_exist(pubkey_path):
        assert create_privatekey(
            os.path.join(os.path.split(pubkey_path)[0], "privkey.pem")
        )
        assert create_publickey(
            os.path.join(os.path.split(pubkey_path)[0], "privkey.pem"),
            pubkey_path
        )
    return pubkey_path
