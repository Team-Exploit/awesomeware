import string

IV_BYTES = 16

def generate_iv() -> str:
    return ''.join(
        random.choices(
            string.ascii_lowercase + string.digits,
            k=IV_BYTES))

def my_encrypt(message: str, key: str, **kwargs) -> tuple:
    """
    Encrypt a string of ascii text using a 32B key and
    a 16B initialisation vector IV
    If the IV is not provided, one will be generated
    args:
        message: str
        key: str
    kwargs:
        iv: str
    return: (ciphertext:str, IV: str)
    """
    iv = kwargs.get("iv", generate_iv())
    ## TODO
    ciphertext = ""
    return ciphertext, iv

def my_decrypt(ciphertext, key, init_v) -> tuple:
    ## TODO
    plaintext = ""
    return plaintext, init_v

def my_file_encrypt(filepath: str) -> tuple:
    """
    Encrypt a file at the given path
    args:
        filepath: str
    """
    ## TODO
    ciphertext = ""
    iv = ""
    key = ""
    ext = ""
    return ciphertext, iv, key, ext

def my_file_decrypt(filepath: str) -> tuple:
    ## TODO
    plaintext = ""
    iv = ""
    key = ""
    ext = ""
    return plaintext, iv, key, ext

def main():
    pass

if __name__ == "__main__":
    main()
