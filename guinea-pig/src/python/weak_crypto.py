# CWE-327, CWE-328: Use of a Broken or Risky Cryptographic Algorithm / Weak Hash
# MD5 used to hash passwords; DES in ECB mode used for encryption.
# Expected detecting family: sast
import hashlib

try:
    from Crypto.Cipher import DES  # pycryptodome
except ImportError:  # keep file importable without the dep
    DES = None


def hash_password(password):
    # VULNERABLE SINK: MD5 is a broken hash for passwords (CWE-328)
    return hashlib.md5(password.encode()).hexdigest()


def hash_token(token):
    # VULNERABLE SINK: SHA1 is also broken for security use (CWE-327/328)
    return hashlib.sha1(token.encode()).hexdigest()


def encrypt(data, key):
    # VULNERABLE SINK: DES in ECB mode (CWE-327) - weak cipher, no IV
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)


if __name__ == "__main__":
    print(hash_password("hunter2"))
