# One-Time Pad Encryption Tool

A cross-platform GUI application for encrypting and decrypting messages and files using a One-Time Pad (OTP).

## Features
- Encrypt/decrypt text messages and files using binary one-time pads
- uuencode support for sending encrypted data via any messenger
- OTP usage tracking to prevent reuse
- Cross-platform GUI (Windows, macOS, Linux)
- Large file support with chunked processing

## Requirements
- Python 3.6+
- tkinter (usually included with Python)
- pytest (for running tests)

## Installation
```bash
pip install -r requirements.txt
```

## Usage

### Running the GUI Application
```bash
python otp_gui.py
```

### Running the Example
```bash
python example.py
```

### Running Tests
```bash
pytest tests/
```

## Architecture
The application is organized into several modules:
- `otp_core.py`: Core encryption/decryption logic
- `otp_tracker.py`: OTP usage tracking and persistence
- `encoding.py`: uuencode/uudecode functionality
- `file_handler.py`: Chunked file processing
- `otp_gui.py`: GUI interface

## How It Works
1. **One-Time Pad Encryption**: Uses bitwise XOR between plaintext and random pad
2. **OTP Tracking**: Records used byte ranges to prevent reuse
3. **File Processing**: Processes large files in chunks to maintain responsiveness
4. **Encoding**: Uses uuencode for safe transmission over text-based channels

## Documentation
- [User Manual](docs/user_manual.md): Instructions for using the application
- [Developer Manual](docs/developer_manual.md): Technical documentation for developers

## Security Notes
- Use truly random data for OTPs (not pseudo-random)
- Never reuse any portion of an OTP
- Keep OTPs secret and secure
- The application tracks used ranges to prevent reuse

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.