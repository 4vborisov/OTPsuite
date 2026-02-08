#!/usr/bin/env python3
"""
One-Time Notepad Generator

This application creates a file with random content of a specified size.
The file can be used as a one-time notepad for secure note taking.

Usage:
    python notepad_generator.py -s <size> [-o <output_file>]

Examples:
    python notepad_generator.py -s 100M
    python notepad_generator.py -s 5G -o my_notepad.txt
"""

import argparse
import os
import secrets
import sys
from typing import BinaryIO


def parse_size(size_str: str) -> int:
    """
    Parse a size string with optional units (B, K, M, G, T) and return size in bytes.
    
    Args:
        size_str: Size string with optional unit (e.g., '100M', '5G')
        
    Returns:
        Size in bytes as integer
        
    Raises:
        ValueError: If the size string is invalid
    """
    size_str = size_str.upper().strip()
    
    # Handle empty string
    if not size_str:
        raise ValueError("Size string cannot be empty")
    
    # Define multipliers for each unit
    multipliers = {
        'B': 1,
        'K': 1024,
        'M': 1024 ** 2,
        'G': 1024 ** 3,
        'T': 1024 ** 4
    }
    
    # Extract the numeric part and unit
    if size_str[-1] in multipliers:
        try:
            number = float(size_str[:-1])
            unit = size_str[-1]
        except ValueError:
            raise ValueError(f"Invalid size format: {size_str}")
    else:
        # Assume bytes if no unit specified
        try:
            number = float(size_str)
            unit = 'B'
        except ValueError:
            raise ValueError(f"Invalid size format: {size_str}")
    
    # Calculate size in bytes
    size_bytes = int(number * multipliers[unit])
    
    # Check minimum size requirement (1 byte for testing, but warn if less than 1KB)
    if size_bytes < 1:
        raise ValueError("File size must be at least 1 byte")
    
    return size_bytes


def generate_random_chunk(size: int) -> bytes:
    """
    Generate a chunk of random bytes with enhanced entropy sources.
    
    Args:
        size: Size of chunk in bytes
        
    Returns:
        Random bytes of specified size
    """
    # Start with cryptographically secure random bytes
    chunk = bytearray(secrets.token_bytes(size))
    
    # Add additional entropy from system sources when possible
    try:
        # Add entropy from current time (nanosecond precision)
        import time
        time_entropy = int(time.time_ns()) & 0xFFFFFFFF
        time_bytes = time_entropy.to_bytes(4, byteorder='little')
        
        # Mix time entropy into the chunk
        for i in range(min(4, size)):
            chunk[i] ^= time_bytes[i]
    except:
        # If time_ns is not available, skip this entropy source
        pass
    
    # Add entropy from process ID
    try:
        import os
        pid = os.getpid()
        pid_bytes = pid.to_bytes(4, byteorder='little')
        
        # Mix PID entropy into the chunk
        for i in range(min(4, size)):
            chunk[(i + 4) % size] ^= pid_bytes[i]
    except:
        # If PID is not available, skip this entropy source
        pass
    
    # Add entropy from memory address of the chunk
    try:
        addr = id(chunk)
        addr_bytes = addr.to_bytes(8, byteorder='little')
        
        # Mix address entropy into the chunk
        for i in range(min(8, size)):
            chunk[(i + 8) % size] ^= addr_bytes[i]
    except:
        # If address mixing fails, skip this entropy source
        pass
    
    return bytes(chunk)


def create_notepad_file(file_path: str, size_bytes: int, chunk_size: int = 1024 * 1024) -> None:
    """
    Create a notepad file with random content of specified size.
    
    Args:
        file_path: Path to the output file
        size_bytes: Size of file in bytes
        chunk_size: Size of chunks to write at a time (default 1MB)
    """
    print(f"Creating notepad file: {file_path}")
    print(f"File size: {size_bytes:,} bytes ({format_size(size_bytes)})")
    
    # Check if file already exists
    if os.path.exists(file_path):
        response = input(f"File '{file_path}' already exists. Overwrite? (y/N): ")
        if response.lower() != 'y':
            print("Operation cancelled.")
            return
    
    try:
        with open(file_path, 'wb') as f:
            written_bytes = 0
            
            # Write chunks until we reach the desired size
            while written_bytes < size_bytes:
                # Calculate remaining bytes to write
                remaining_bytes = size_bytes - written_bytes
                current_chunk_size = min(chunk_size, remaining_bytes)
                
                # Generate and write random chunk
                chunk = generate_random_chunk(current_chunk_size)
                f.write(chunk)
                written_bytes += current_chunk_size
                
                # Show progress
                progress = (written_bytes / size_bytes) * 100
                print(f"\rProgress: {progress:.1f}% ({written_bytes:,}/{size_bytes:,} bytes)", end='')
                
        print(f"\nNotepad file '{file_path}' created successfully!")
        
    except IOError as e:
        print(f"Error writing to file: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation interrupted by user. Cleaning up...")
        if os.path.exists(file_path):
            os.remove(file_path)
        sys.exit(1)


def format_size(size_bytes: int) -> str:
    """
    Format size in bytes to human readable format.
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Human readable size string
    """
    if size_bytes == 0:
        return "0B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    size = float(size_bytes)
    
    while size >= 1024.0 and i < len(size_names) - 1:
        size /= 1024.0
        i += 1
    
    return f"{size:.2f} {size_names[i]}"


def main():
    """Main function to parse arguments and create notepad file."""
    parser = argparse.ArgumentParser(
        description="Create a one-time notepad file with random content",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument(
        "-s", "--size",
        required=True,
        help="Size of the notepad file (e.g., 100B, 50K, 10M, 2G, 1T)"
    )
    
    parser.add_argument(
        "-o", "--output",
        default="notepad.txt",
        help="Output file name (default: notepad.txt)"
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    try:
        # Parse the size
        size_bytes = parse_size(args.size)
        
        # Create the notepad file
        create_notepad_file(args.output, size_bytes)
        
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()