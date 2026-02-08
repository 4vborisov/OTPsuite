"""
Tests for the encoding module.
"""
import pytest

from encoding import uuencode, uudecode, pack_metadata, unpack_metadata


def test_uuencode_uudecode_roundtrip():
    """Test uuencode/uudecode roundtrip."""
    data = b"Hello, World! This is a test message."
    
    encoded = uuencode(data)
    decoded = uudecode(encoded)
    
    assert decoded == data


def test_uuencode_uudecode_empty():
    """Test uuencode/uudecode with empty data."""
    data = b""
    
    encoded = uuencode(data)
    decoded = uudecode(encoded)
    
    assert decoded == data


def test_uudecode_malformed():
    """Test uudecode with malformed data."""
    with pytest.raises(ValueError):
        uudecode("invalid data")


def test_metadata_pack_unpack():
    """Test metadata packing and unpacking."""
    otp_filename = "test.pad"
    offset = 100
    length = 50
    checksum = "abc123"
    
    packed = pack_metadata(otp_filename, offset, length, checksum)
    unpacked = unpack_metadata(packed)
    
    assert unpacked == (otp_filename, offset, length, checksum)


def test_metadata_pack_unpack_empty():
    """Test metadata packing and unpacking with empty values."""
    otp_filename = ""
    offset = 0
    length = 0
    checksum = ""
    
    packed = pack_metadata(otp_filename, offset, length, checksum)
    unpacked = unpack_metadata(packed)
    
    assert unpacked == (otp_filename, offset, length, checksum)