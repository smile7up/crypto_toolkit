import base64
import json
import urllib.parse

import hashlib
import secrets
import string

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