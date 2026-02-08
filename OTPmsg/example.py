"""
Example usage of the One-Time Pad encryption tool.
"""
import os
import tempfile

from otp_core import encrypt_data, decrypt_data, calculate_checksum
from otp_tracker import OTPTracker
from encoding import uuencode, uudecode, pack_metadata, unpack_metadata


def create_sample_otp(filename, size):
    """Create a sample OTP file with random data."""
    with open(filename, 'wb') as f:
        f.write(os.urandom(size))


def demonstrate_text_encryption():
    """Demonstrate text encryption and decryption."""
    print("=== Text Encryption Demonstration ===")
    
    # Create a sample OTP
    otp_file = "sample.pad"
    create_sample_otp(otp_file, 1000)
    
    # Text to encrypt
    plaintext = "This is a secret message!"
    print(f"Original text: {plaintext}")
    
    # Convert to bytes
    data = plaintext.encode('utf-8')
    
    # Read OTP data
    with open(otp_file, 'rb') as f:
        pad = f.read(len(data))
    
    # Encrypt
    encrypted = encrypt_data(data, pad, 0)
    print(f"Encrypted (bytes): {encrypted}")
    
    # Pack metadata
    checksum = calculate_checksum(data)
    metadata = pack_metadata(otp_file, 0, len(data), checksum)
    payload = metadata + encrypted
    
    # Encode for transmission
    encoded = uuencode(payload)
    print(f"Encoded for transmission:\n{encoded}")
    
    # Decode
    decoded_payload = uudecode(encoded)
    
    # Extract metadata
    extracted_filename, offset, length, extracted_checksum = unpack_metadata(decoded_payload)
    encrypted_data = decoded_payload[len(decoded_payload) - length:]
    
    # Read OTP data again
    with open(otp_file, 'rb') as f:
        pad = f.read(length)
    
    # Decrypt
    decrypted = decrypt_data(encrypted_data, pad, 0)
    decrypted_text = decrypted.decode('utf-8')
    print(f"Decrypted text: {decrypted_text}")
    
    # Verify checksum
    if calculate_checksum(decrypted) == extracted_checksum:
        print("Checksum verified: Data integrity confirmed")
    else:
        print("Checksum failed: Data may be corrupted")
    
    # Clean up
    os.remove(otp_file)


def demonstrate_otp_tracking():
    """Demonstrate OTP usage tracking."""
    print("\n=== OTP Tracking Demonstration ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        metadata_file = os.path.join(temp_dir, "usage.json")
        tracker = OTPTracker(metadata_file)
        
        otp_filename = "sample.pad"
        
        # Check if we can use a range
        if tracker.can_use_range(otp_filename, 0, 100):
            print("Can use range 0-100 for encryption")
            tracker.record_usage(otp_filename, 0, 100, "checksum1")
        else:
            print("Cannot use range 0-100 (already used)")
        
        # Try to use overlapping range
        if tracker.can_use_range(otp_filename, 50, 100):
            print("Can use range 50-150 for encryption")
        else:
            print("Cannot use range 50-150 (overlaps with used range)")
        
        # Try to use non-overlapping range
        if tracker.can_use_range(otp_filename, 200, 100):
            print("Can use range 200-300 for encryption")
            tracker.record_usage(otp_filename, 200, 100, "checksum2")
        else:
            print("Cannot use range 200-300 (overlaps with used range)")


if __name__ == "__main__":
    demonstrate_text_encryption()
    demonstrate_otp_tracking()