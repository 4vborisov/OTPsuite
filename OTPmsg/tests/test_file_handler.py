"""
Tests for the file handler module.
"""
import os
import tempfile
import pytest

from file_handler import read_file_chunks, write_file_chunks, get_file_size


def test_read_file_chunks():
    """Test reading file in chunks."""
    with tempfile.TemporaryDirectory() as temp_dir:
        test_file = os.path.join(temp_dir, "test.txt")
        
        # Create test file
        content = b"a" * 1000  # 1000 bytes
        with open(test_file, "wb") as f:
            f.write(content)
        
        # Read in chunks
        chunks = list(read_file_chunks(test_file, chunk_size=100))
        
        # Should have 10 chunks of 100 bytes each
        assert len(chunks) == 10
        assert all(len(chunk) == 100 for chunk in chunks)
        
        # Reassemble content
        reassembled = b"".join(chunks)
        assert reassembled == content


def test_write_file_chunks():
    """Test writing file from chunks."""
    with tempfile.TemporaryDirectory() as temp_dir:
        test_file = os.path.join(temp_dir, "output.txt")
        
        # Create test chunks
        chunks = [b"chunk1", b"chunk2", b"chunk3"]
        
        # Write chunks to file
        write_file_chunks(test_file, iter(chunks))
        
        # Verify content
        with open(test_file, "rb") as f:
            content = f.read()
        
        assert content == b"chunk1chunk2chunk3"


def test_get_file_size():
    """Test getting file size."""
    with tempfile.TemporaryDirectory() as temp_dir:
        test_file = os.path.join(temp_dir, "test.txt")
        
        # Create test file
        content = b"Hello, World!"  # 13 bytes
        with open(test_file, "wb") as f:
            f.write(content)
        
        # Get size
        size = get_file_size(test_file)
        
        assert size == 13


def test_get_file_size_nonexistent():
    """Test getting size of nonexistent file."""
    with pytest.raises(IOError):
        get_file_size("/nonexistent/file.txt")