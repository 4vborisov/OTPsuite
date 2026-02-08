# One-Time Pad Encryption Tool - Developer Manual

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Module Responsibilities](#module-responsibilities)
3. [Design Decisions](#design-decisions)
4. [Known Limitations](#known-limitations)
5. [Testing](#testing)
6. [Extending the Application](#extending-the-application)

## Architecture Overview

The application follows a modular architecture with clear separation of concerns:

```
otp_gui.py          <- Main GUI application
otp_core.py         <- Core encryption/decryption logic
otp_tracker.py      <- OTP usage tracking
encoding.py         <- Encoding/decoding functionality
file_handler.py    <- File I/O with chunked processing
tests/              <- Test suite
docs/               <- Documentation
```

### Data Flow
1. User interacts with GUI (otp_gui.py)
2. GUI calls appropriate functions in core modules
3. Core modules process data and return results
4. GUI displays results to user

### Threading Model
- GUI operations run on the main thread
- File operations run on background threads to maintain responsiveness
- Thread-safe operations use appropriate locking mechanisms

## Module Responsibilities

### otp_core.py
Handles the core cryptographic operations:
- XOR encryption/decryption
- Checksum calculation and verification

Key functions:
- `xor_bytes()`: Performs XOR operation on byte sequences
- `encrypt_data()`: Encrypts data with OTP at specified offset
- `decrypt_data()`: Decrypts data with OTP at specified offset
- `calculate_checksum()`: Calculates SHA-256 checksum
- `verify_checksum()`: Verifies data integrity

### otp_tracker.py
Manages OTP usage tracking to prevent reuse:
- Tracks used byte ranges
- Detects overlaps
- Persists usage data to JSON file

Key classes:
- `Range`: Represents a byte range with overlap detection
- `OTPTracker`: Manages usage tracking for OTP files

Key functions:
- `check_overlap()`: Checks if a range overlaps with used ranges
- `record_usage()`: Records usage of an OTP range
- `can_use_range()`: Checks if a range can be used for encryption

### encoding.py
Handles encoding and decoding of data for transmission:
- uuencode/uudecode implementation
- Metadata packing/unpacking

Key functions:
- `uuencode()`: Encodes binary data using uuencoding
- `uudecode()`: Decodes uuencoded data
- `pack_metadata()`: Packs metadata into binary format
- `unpack_metadata()`: Unpacks metadata from binary format

### file_handler.py
Manages file I/O with chunked processing for large files:
- Reading files in chunks
- Writing files from chunks
- File size operations

Key functions:
- `read_file_chunks()`: Reads a file in chunks
- `write_file_chunks()`: Writes chunks to a file
- `get_file_size()`: Gets the size of a file

### otp_gui.py
Provides the cross-platform GUI interface:
- Text encryption/decryption
- File encryption/decryption
- OTP management
- User interaction handling

Key classes:
- `OTPEncryptionApp`: Main application class

## Design Decisions

### Choice of GUI Framework
**tkinter** was chosen for the following reasons:
- Cross-platform compatibility
- Part of Python standard library (no external dependencies)
- Simple to use and well-documented
- Sufficient for the application's needs

### OTP Tracking Approach
- **Persistent storage**: Usage data is stored in a JSON file for persistence across sessions
- **Range-based tracking**: Tracks byte ranges rather than individual bytes for efficiency
- **Overlap detection**: Prevents reuse of OTP segments for encryption

### Encoding Method
- **uuencode**: Chosen for its widespread support and ASCII output
- **Metadata embedding**: Metadata is packed with the encrypted data for self-contained messages

### File Processing
- **Chunked processing**: Large files are processed in chunks to maintain responsiveness
- **Background threads**: File operations run on separate threads to prevent GUI blocking

### Error Handling
- **User-friendly messages**: Technical errors are translated into user-friendly messages
- **Graceful degradation**: The application fails safely with clear error messages

## Known Limitations

### Performance
- **Memory usage**: Large files are processed in chunks, but metadata operations may require loading entire files
- **File I/O**: Performance depends on disk I/O speed

### Security
- **Metadata exposure**: Metadata is not encrypted and could reveal information about the encrypted data
- **Checksum security**: SHA-256 is used for integrity checking, but this doesn't provide authentication

### Usability
- **Manual OTP management**: Users must manually manage OTP files and offsets
- **No automatic OTP generation**: The application doesn't generate OTPs (security by design)

### Platform Limitations
- **File path handling**: May have issues with very long file paths on some platforms
- **Clipboard handling**: Clipboard operations may behave differently on different platforms

## Testing

### Test Suite Structure
The test suite uses pytest and is organized as follows:
- `test_otp_core.py`: Tests for core cryptographic functions
- `test_otp_tracker.py`: Tests for OTP usage tracking
- `test_encoding.py`: Tests for encoding/decoding functions
- `test_file_handler.py`: Tests for file handling functions

### Running Tests
To run the test suite:
```bash
pytest tests/
```

### Test Coverage
The tests cover:
- **Unit tests**: Individual function behavior
- **Integration tests**: Module interaction
- **Edge cases**: Boundary conditions and error handling
- **Large data**: Chunked processing with large data sets

## Extending the Application

### Adding New Features
To add new features:
1. Identify the appropriate module for the new functionality
2. Implement the core logic in the appropriate module
3. Add GUI elements in otp_gui.py
4. Add tests in the tests/ directory
5. Update documentation

### Adding New Encoding Methods
To add support for new encoding methods:
1. Implement encode/decode functions in encoding.py
2. Add GUI elements for the new encoding method
3. Update the encryption/decryption workflows to support the new method

### Adding New GUI Elements
To add new GUI elements:
1. Modify otp_gui.py to add new UI elements
2. Implement the backend logic in the appropriate modules
3. Add tests for the new functionality

### Improving Performance
Potential performance improvements:
- **Asynchronous I/O**: Use asyncio for file operations
- **Memory mapping**: Use memory-mapped files for large OTPs
- **Caching**: Cache frequently accessed OTP segments