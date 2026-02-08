"""
Tests for the OTP core module.
"""
import os
import tempfile
import pytest

from otp_core import xor_bytes, encrypt_data, decrypt_data, calculate_checksum, verify_checksum


def test_xor_bytes():
    """Test XOR operation."""
    data = b"hello"
    pad = b"world"
    expected = bytes([h ^ w for h, w in zip(data, pad)])
    
    result = xor_bytes(data, pad)
    
    assert result == expected


def test_xor_bytes_length_mismatch():
    """Test XOR with mismatched lengths."""
    data = b"hello"
    pad = b"wo"
    
    with pytest.raises(ValueError):
        xor_bytes(data, pad)


def test_encrypt_decrypt_roundtrip():
    """Test encryption and decryption roundtrip."""
    plaintext = b"Hello, World!"
    pad = b"This is a pad1"
    
    # Encrypt
    encrypted = encrypt_data(plaintext, pad, 0)
    
    # Decrypt
    decrypted = decrypt_data(encrypted, pad, 0)
    
    assert decrypted == plaintext


def test_encrypt_with_offset():
    """Test encryption with offset."""
    plaintext = b"Hello"
    pad = b"123456789012345"
    offset = 5
    
    # Encrypt with offset
    encrypted = encrypt_data(plaintext, pad, offset)
    
    # Decrypt with offset
    decrypted = decrypt_data(encrypted, pad, offset)
    
    assert decrypted == plaintext


def test_encrypt_insufficient_pad():
    """Test encryption with insufficient pad."""
    plaintext = b"Hello, World!"
    pad = b"Short"
    
    with pytest.raises(ValueError):
        encrypt_data(plaintext, pad, 0)


def test_checksum():
    """Test checksum calculation and verification."""
    data = b"Hello, World!"
    checksum = calculate_checksum(data)
    
    assert isinstance(checksum, str)
    assert len(checksum) == 64  # SHA-256 hex digest length
    
    # Verify correct data
    assert verify_checksum(data, checksum)
    
    # Verify incorrect data
    assert not verify_checksum(b"Different data", checksum)