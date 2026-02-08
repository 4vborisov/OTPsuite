"""
File handling with chunked processing for large files.
"""
import os
from typing import Generator, Callable


# Default chunk size for file processing (1MB)
DEFAULT_CHUNK_SIZE = 1024 * 1024


def read_file_chunks(filepath: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Generator[bytes, None, None]:
    """
    Read a file in chunks.
    
    Args:
        filepath: Path to the file
        chunk_size: Size of each chunk in bytes
        
    Yields:
        Chunks of file data
        
    Raises:
        IOError: If the file cannot be read
    """
    try:
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                yield chunk
    except Exception as e:
        raise IOError(f"Cannot read file {filepath}: {str(e)}")


def write_file_chunks(filepath: str, chunks: Generator[bytes, None, None]):
    """
    Write chunks to a file.
    
    Args:
        filepath: Path to the file
        chunks: Generator of data chunks
        
    Raises:
        IOError: If the file cannot be written
    """
    try:
        with open(filepath, 'wb') as f:
            for chunk in chunks:
                f.write(chunk)
    except Exception as e:
        raise IOError(f"Cannot write file {filepath}: {str(e)}")


def process_file_with_callback(filepath: str, callback: Callable[[bytes], bytes], 
                                chunk_size: int = DEFAULT_CHUNK_SIZE) -> Generator[bytes, None, None]:
    """
    Process a file with a callback function on each chunk.
    
    Args:
        filepath: Path to the file
        callback: Function to process each chunk
        chunk_size: Size of each chunk in bytes
        
    Yields:
        Processed chunks
        
    Raises:
        IOError: If the file cannot be read
    """
    for chunk in read_file_chunks(filepath, chunk_size):
        yield callback(chunk)


def get_file_size(filepath: str) -> int:
    """
    Get the size of a file in bytes.
    
    Args:
        filepath: Path to the file
        
    Returns:
        Size of the file in bytes
        
    Raises:
        IOError: If the file cannot be accessed
    """
    try:
        return os.path.getsize(filepath)
    except Exception as e:
        raise IOError(f"Cannot access file {filepath}: {str(e)}")