import base64
import json
import urllib.parse

import hashlib
import secrets
import string
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

def encode_base64(input_string: str) -> str:
    """
    Encodes a string to Base64.

    Args:
        input_string: The string to encode.

    Returns:
        The Base64 encoded string.
    """
    try:
        input_bytes = input_string.encode('utf-8')
        encoded_bytes = base64.b64encode(input_bytes)
        return encoded_bytes.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Failed to encode to Base64: {e}")

def encrypt_aes_gcm(input_string: str, key: str) -> str:
    """
    Encrypts a string using AES-GCM.

    Args:
        input_string: The string to encrypt.
        key: The encryption key (must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256).

    Returns:
        A JSON string containing the base64-encoded ciphertext, nonce, and tag.
    """
    try:
        key_bytes = key.encode('utf-8')
        if len(key_bytes) not in [16, 24, 32]:
            raise ValueError("AES key must be 16, 24, or 32 bytes long.")

        data_bytes = input_string.encode('utf-8')

        # Create a new AES cipher object with GCM mode
        cipher = AES.new(key_bytes, AES.MODE_GCM)
        
        # Encrypt the data
        ciphertext, tag = cipher.encrypt_and_digest(data_bytes)

        # The nonce is generated automatically and can be accessed via cipher.nonce
        nonce = cipher.nonce

        # Combine and encode for easy transport
        result = {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8')
        }
        return json.dumps(result)
    except Exception as e:
        raise ValueError(f"Failed to encrypt with AES-GCM: {e}")

def decrypt_aes_gcm(encrypted_data_json: str, key: str) -> str:
    """
    Decrypts a string using AES-GCM.

    Args:
        encrypted_data_json: A JSON string containing the base64-encoded
                             'ciphertext', 'nonce', and 'tag'.
        key: The decryption key (must be 16, 24, or 32 bytes long).

    Returns:
        The decrypted string.

    Raises:
        ValueError: If decryption fails (e.g., wrong key, tampered data).
    """
    try:
        key_bytes = key.encode('utf-8')
        if len(key_bytes) not in [16, 24, 32]:
            raise ValueError("AES key must be 16, 24, or 32 bytes long.")

        encrypted_data = json.loads(encrypted_data_json)
        nonce = base64.b64decode(encrypted_data['nonce'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        tag = base64.b64decode(encrypted_data['tag'])

        cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
        decrypted_bytes = cipher.decrypt_and_verify(ciphertext, tag)

        return decrypted_bytes.decode('utf-8')
    except (ValueError, KeyError, json.JSONDecodeError) as e:
        raise ValueError(f"Decryption failed. Check if the key is correct and the data is a valid, untampered JSON from the encryption tool. Error: {e}")

def encode_url(input_string: str) -> str:
    """
    URL-encodes a string using percent-encoding.

    Args:
        input_string: The string to encode.

    Returns:
        The URL-encoded string.
    """
    try:
        return urllib.parse.quote_plus(input_string)
    except Exception as e:
        raise ValueError(f"Failed to URL-encode string: {e}")

def decode_url(input_string: str) -> str:
    """
    URL-decodes a string.

    Args:
        input_string: The string to decode.

    Returns:
        The URL-decoded string.
    """
    try:
        return urllib.parse.unquote_plus(input_string)
    except Exception as e:
        raise ValueError(f"Failed to URL-decode string: {e}")

def calculate_sha256(input_string: str) -> str:
    """
    Calculates the SHA-256 hash of a string.

    Args:
        input_string: The string to hash.

    Returns:
        The SHA-256 hash as a hex digest string.
    """
    try:
        input_bytes = input_string.encode('utf-8')
        hash_object = hashlib.sha256(input_bytes)
        return hash_object.hexdigest()
    except Exception as e:
        raise ValueError(f"Failed to calculate SHA-256 hash: {e}")

def calculate_md5(input_string: str) -> str:
    """
    Calculates the MD5 hash of a string.

    Args:
        input_string: The string to hash.

    Returns:
        The MD5 hash as a hex digest string.
    """
    try:
        input_bytes = input_string.encode('utf-8')
        hash_object = hashlib.md5(input_bytes)
        return hash_object.hexdigest()
    except Exception as e:
        raise ValueError(f"Failed to calculate MD5 hash: {e}")

def generate_secure_key(key_length_bytes: int) -> str:
    """
    Generates a cryptographically secure key as a string suitable for the AES tool.
    The key is composed of ASCII letters and digits, ensuring each character is one byte.

    Args:
        key_length_bytes: The desired key length in bytes (16, 24, or 32).

    Returns:
        A random string of the specified length.
    """
    if key_length_bytes not in [16, 24, 32]:
        raise ValueError("Key length must be 16, 24, or 32 bytes.")

    # Use ASCII letters and digits for a safe, predictable character set.
    alphabet = string.ascii_letters + string.digits
    key = ''.join(secrets.choice(alphabet) for i in range(key_length_bytes))
    return key