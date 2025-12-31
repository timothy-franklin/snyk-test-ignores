"""
Additional cryptographic and security vulnerabilities for SAST testing
"""

import hashlib
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# Weak hash functions
def weak_password_hash(password):
    """Using SHA1 for password hashing"""
    return hashlib.sha1(password.encode()).hexdigest()


def another_weak_hash(data):
    """Using MD5"""
    return hashlib.md5(data.encode()).hexdigest()


# Insecure cipher modes
def encrypt_with_ecb(data, key):
    """ECB mode is insecure"""
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


# Hardcoded encryption keys
def encrypt_sensitive_data(data):
    """Hardcoded encryption key"""
    key = b'sixteen byte key'
    iv = b'1234567890123456'
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


# Insecure random for security purposes
def generate_session_id():
    """Using random for security-sensitive operation"""
    return ''.join([chr(random.randint(65, 90)) for _ in range(32)])


# AWS/API keys hardcoded
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_API_KEY = "sk_live_1234567890abcdefghijklmnop"
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"


def connect_to_aws():
    """Hardcoded AWS credentials"""
    return {
        'access_key': AWS_ACCESS_KEY,
        'secret_key': AWS_SECRET_KEY
    }
