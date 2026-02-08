"""
Encoding and decoding functionality for OTP messages.
"""
import binascii
import struct
from typing import Tuple


def uuencode(data: bytes) -> str:
    """
    Encode binary data using uuencoding.
    
    Args:
        data: Binary data to encode
        
    Returns:
        Uuencoded string
    """
    # Standard uuencode line length is 45 bytes
    # Each line: length byte + encoded data + newline
    lines = []
    
    # Process data in 45-byte chunks
    for i in range(0, len(data), 45):
        chunk = data[i:i+45]
        # Length character (add 32 to length)
        length_char = chr(len(chunk) + 32)
        # Encode the chunk
        encoded_chunk = binascii.b2a_uu(chunk).decode('ascii').strip()
        lines.append(length_char + encoded_chunk)
    
    # Add end marker
    lines.append("`")
    
    return '\n'.join(lines)


def uudecode(encoded_data: str) -> bytes:
    """
    Decode uuencoded data.
    
    Args:
        encoded_data: Uuencoded string
        
    Returns:
        Decoded binary data
        
    Raises:
        ValueError: If the encoded data is malformed
    """
    lines = encoded_data.strip().split('\n')
    decoded_parts = []
    
    for line in lines:
        if line == "`":
            # End marker
            break
            
        if not line:
            continue
            
        try:
            # First character is length + 32
            length = ord(line[0]) - 32
            if length < 0 or length > 45:
                raise ValueError("Invalid length character")
            
            # Decode the rest of the line
            encoded_part = line[1:].encode('ascii')
            decoded_part = binascii.a2b_uu(encoded_part)
            decoded_parts.append(decoded_part)
        except Exception as e:
            raise ValueError(f"Malformed uuencoded data: {str(e)}")
    
    return b''.join(decoded_parts)


def pack_metadata(otp_filename: str, offset: int, length: int, checksum: str) -> bytes:
    """
    Pack metadata into a binary format.
    
    Args:
        otp_filename: Name of the OTP file
        offset: Offset in the OTP file
        length: Length of the encrypted data
        checksum: Checksum of the encrypted data
        
    Returns:
        Packed metadata as bytes
    """
    # Pack as: filename length (4 bytes) + filename + offset (8 bytes) + length (8 bytes) + checksum length (4 bytes) + checksum
    filename_bytes = otp_filename.encode('utf-8')
    checksum_bytes = checksum.encode('utf-8')
    
    packed = struct.pack(
        '<I{}sQQL{}s'.format(len(filename_bytes), len(checksum_bytes)),
        len(filename_bytes),
        filename_bytes,
        offset,
        length,
        len(checksum_bytes),
        checksum_bytes
    )
    
    return packed


def unpack_metadata(data: bytes) -> Tuple[str, int, int, str]:
    """
    Unpack metadata from binary format.
    
    Args:
        data: Packed metadata
        
    Returns:
        Tuple of (otp_filename, offset, length, checksum)
        
    Raises:
        ValueError: If the data is malformed
    """
    try:
        # Read filename length
        filename_len = struct.unpack('<I', data[:4])[0]
        
        # Read filename
        filename_bytes = data[4:4+filename_len]
        otp_filename = filename_bytes.decode('utf-8')
        
        # Read offset and length
        offset, length = struct.unpack('<QQ', data[4+filename_len:4+filename_len+16])
        
        # Read checksum length
        checksum_len_offset = 4 + filename_len + 16
        checksum_len = struct.unpack('<L', data[checksum_len_offset:checksum_len_offset+4])[0]
        
        # Read checksum
        checksum_bytes = data[checksum_len_offset+4:checksum_len_offset+4+checksum_len]
        checksum = checksum_bytes.decode('utf-8')
        
        return otp_filename, offset, length, checksum
    except Exception as e:
        raise ValueError(f"Malformed metadata: {str(e)}")