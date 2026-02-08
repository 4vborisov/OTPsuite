# OTPsuite - One-Time Pad Encryption Tools

A comprehensive suite of tools for One-Time Pad (OTP) encryption, providing secure random data generation and message encryption/decryption capabilities.

## Overview

This repository contains two main components:
1. **OTPg** - Tools for generating cryptographically secure random data and analyzing randomness
2. **OTPmsg** - Complete message encryption/decryption system with GUI

The One-Time Pad is theoretically unbreakable when used correctly, making it the strongest encryption method possible. This suite provides all necessary tools to implement OTP encryption properly.

## Components

### OTPg (One-Time Pad Generator)
Tools for generating and analyzing cryptographically secure random data:
- `notepad_generator.py` - Generates secure random data suitable for OTP keys
- `randomness_analyzer.py` - Analyzes the quality of random data
- Test suite for verification

### OTPmsg (One-Time Pad Message)
Complete message encryption system:
- `otp_core.py` - Core encryption/decryption algorithms
- `encoding.py` - Text encoding/decoding utilities
- `file_handler.py` - Secure file handling
- `otp_tracker.py` - Key usage tracking to prevent reuse
- `otp_gui.py` - User-friendly graphical interface
- Cross-platform launch scripts (`run_app.bat`, `run_app.py`, `run_app.sh`)
- Comprehensive documentation (user and developer manuals)
- Full test suite

## Features

- **Cryptographically Secure**: Uses system-provided randomness sources
- **Key Reuse Prevention**: Tracks key usage to maintain security
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **User-Friendly GUI**: Simple interface for non-technical users
- **Comprehensive Testing**: Extensive test suites for all components
- **Documentation**: Both user and developer manuals included
- **File Handling**: Secure encryption of text and binary files

## Installation

### Prerequisites
- Python 3.6+
- Required packages listed in each component's `requirements.txt`

### Setup
```bash
# For OTPg component
pip install -r OTPg/requirements.txt

# For OTPmsg component
pip install -r OTPmsg/requirements.txt
```

## Usage

### OTPg (Random Data Generation)
```bash
cd OTPg
python notepad_generator.py
python randomness_analyzer.py
```

### OTPmsg (Message Encryption)
```bash
cd OTPmsg
# Using the GUI (recommended)
python otp_gui.py

# Command line interface
python run_app.py

# Run tests
python run_tests.py
```

## Documentation

- [User Manual](OTPmsg/docs/user_manual.md) - Instructions for end users
- [Developer Manual](OTPmsg/docs/developer_manual.md) - Technical documentation and API reference

## Testing

Each component includes a comprehensive test suite:
```bash
# Test OTPg
cd OTPg
python -m pytest

# Test OTPmsg
cd OTPmsg
python run_tests.py
```

## Security Notes

1. **Key Distribution**: Securely sharing OTP keys is the biggest challenge. Keys must be exchanged through secure physical channels.
2. **Key Storage**: Store keys securely and destroy them after use.
3. **Key Reuse**: Never reuse keys - this completely breaks OTP security.
4. **Key Length**: Keys must be at least as long as the message being encrypted.

## License

See individual components for licensing information:
- [OTPg License](OTPg/LICENSE)
- [OTPmsg License](OTPmsg/LICENSE)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

Please ensure all tests pass and add new tests for any functionality changes.

## Disclaimer

This software is provided for educational purposes. The authors are not responsible for any misuse or security breaches. Users are responsible for proper key management and following cryptographic best practices.
