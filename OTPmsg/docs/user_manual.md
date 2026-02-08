# One-Time Pad Encryption Tool - User Manual

## Table of Contents
1. [Introduction](#introduction)
2. [How One-Time Pad Works](#how-one-time-pad-works)
3. [Installing the Application](#installing-the-application)
4. [Using the GUI](#using-the-gui)
   - [Text Encryption](#text-encryption)
   - [File Encryption](#file-encryption)
   - [OTP Management](#otp-management)
5. [Security Considerations](#security-considerations)
6. [Troubleshooting](#troubleshooting)

## Introduction

The One-Time Pad Encryption Tool is a cross-platform application that allows you to encrypt and decrypt messages and files using the proven one-time pad encryption method. This method, when used correctly, provides theoretically unbreakable encryption.

## How One-Time Pad Works

One-time pad encryption is a method where plaintext is combined with a random secret key (the pad) of the same length. The encryption process uses the XOR operation:

```
Ciphertext = Plaintext XOR Pad
Plaintext = Ciphertext XOR Pad
```

### Key Properties
- **Perfect secrecy**: When used correctly, OTP provides information-theoretic security
- **Key requirements**: The pad must be truly random, as long as the message, and never reused
- **Security**: If any of these requirements are violated, security is compromised

## Installing the Application

### Requirements
- Python 3.6 or higher
- tkinter (usually included with Python)

### Installation Steps
1. Ensure Python is installed on your system
2. Download or clone the application files
3. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Using the GUI

The application has three main tabs: Text Encryption, File Encryption, and OTP Management.

### Text Encryption

#### Encrypting Text
1. Enter your plaintext in the "Text to Encrypt/Decrypt" field
2. Select an OTP file using the "Browse..." button in the File tab or specify the path directly
3. Set the offset (default is 0)
4. Click "Encrypt Text"
5. The encrypted result will appear in the "Result" field, encoded for safe transmission

#### Decrypting Text
1. Paste the uuencoded encrypted text into the "Text to Encrypt/Decrypt" field
2. Select the same OTP file used for encryption
3. Click "Decrypt Text"
4. The original plaintext will appear in the "Result" field

#### Copying and Pasting
- Use "Copy to Clipboard" to copy the result
- Use "Paste from Clipboard" to paste encoded text for decryption

### File Encryption

#### Encrypting Files
1. Select a file to encrypt using the "Browse..." button
2. Select an OTP file
3. Set the offset (default is 0)
4. Click "Encrypt File"
5. The encrypted file will be saved with a `.encrypted` extension

#### Decrypting Files
1. Select an encrypted file
2. Select the OTP file used for encryption
3. Click "Decrypt File"
4. The decrypted file will be saved with a `.decrypted` extension

### OTP Management

This tab allows you to view information about your OTP files:
- File size
- Used byte ranges
- Overlap warnings

To view information:
1. Select an OTP file using the "Browse..." button
2. Click "Refresh Info" to display usage statistics

## Security Considerations

### OTP Generation
- Use truly random data for OTPs (e.g., from hardware random number generators)
- Never use pseudo-random number generators for OTPs
- Keep OTPs secret and secure

### OTP Usage
- Never reuse any portion of an OTP for encryption
- The application tracks used ranges to prevent reuse
- Always use sufficient offset values to avoid overlap

### Transmission Security
- The application uses uuencode for safe ASCII transmission
- Verify the integrity of received messages
- Be cautious of man-in-the-middle attacks

### Storage Security
- Store OTP files securely
- The application stores usage metadata in `otp_usage.json`
- Protect this file from unauthorized access

## Troubleshooting

### Common Issues

#### "Pad is too short" Error
- Ensure your OTP file is at least as long as the data you're encrypting
- Use a larger offset if you've used portions of the OTP before

#### "This OTP range has already been used" Warning
- The application prevents OTP reuse for encryption
- Use a different offset or a new OTP file

#### "Data integrity check failed" Error
- The decrypted data doesn't match the original checksum
- Verify you're using the correct OTP file and offset

### Performance with Large Files
- The application processes large files in chunks to maintain responsiveness
- Progress is indicated with a progress bar during file operations

### Getting Help
If you encounter issues not covered in this manual, please check:
1. That all file paths are correct
2. That you have read/write permissions for all files
3. That your OTP files are truly random and sufficiently large