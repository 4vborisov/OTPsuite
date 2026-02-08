"""
Core One-Time Pad encryption and decryption logic.
"""
import hashlib
import os
from typing import Tuple


def xor_bytes(data: bytes, pad: bytes) -> bytes:
    """
    XOR two byte sequences together.
    
    Args:
        data: The data to encrypt/decrypt
        pad: The one-time pad to use
        
    Returns:
        The XORed result
        
    Raises:
        ValueError: If pad is shorter than data
    """
    if len(pad) < len(data):
        raise ValueError("Pad is shorter than data")
    
    return bytes(a ^ b for a, b in zip(data, pad))


def encrypt_data(data: bytes, pad: bytes, offset: int) -> bytes:
    """
    Encrypt data using a one-time pad at the specified offset.
    
    Args:
        data: The data to encrypt
        pad: The one-time pad
        offset: The offset in the pad to start encryption
        
    Returns:
        The encrypted data
        
    Raises:
        ValueError: If pad is too short for the data at the given offset
    """
    if offset + len(data) > len(pad):
        raise ValueError("Pad is too short for data at specified offset")
    
    pad_segment = pad[offset:offset + len(data)]
    return xor_bytes(data, pad_segment)


def decrypt_data(encrypted_data: bytes, pad: bytes, offset: int) -> bytes:
    """
    Decrypt data using a one-time pad at the specified offset.
    
    Args:
        encrypted_data: The data to decrypt
        pad: The one-time pad
        offset: The offset in the pad where encryption started
        
    Returns:
        The decrypted data
        
    Raises:
        ValueError: If pad is too short for the encrypted data at the given offset
    """
    if offset + len(encrypted_data) > len(pad):
        raise ValueError("Pad is too short for encrypted data at specified offset")
    
    pad_segment = pad[offset:offset + len(encrypted_data)]
    return xor_bytes(encrypted_data, pad_segment)


def calculate_checksum(data: bytes) -> str:
    """
    Calculate a checksum for data integrity verification.
    
    Args:
        data: The data to checksum
        
    Returns:
        Hexadecimal representation of the SHA-256 hash
    """
    return hashlib.sha256(data).hexdigest()


def verify_checksum(data: bytes, checksum: str) -> bool:
    """
    Verify data integrity using a checksum.
    
    Args:
        data: The data to verify
        checksum: The expected checksum
        
    Returns:
        True if checksums match, False otherwise
    """
    return calculate_checksum(data) == checksum