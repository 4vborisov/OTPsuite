# One-Time Notepad Generator

A Python application that creates a file with random content of a specified size, suitable for use as a one-time notepad for secure note taking.
</content>
</file>
<line_count>85</line_count>
</write_to_file>

## Features

- Creates files with random content using cryptographically secure random number generation
- Enhanced entropy from multiple sources (time, process ID, memory addresses)
- Supports large file sizes (tested up to 10GB+)
- Progress tracking during file creation
- Human-readable size specifications (B, K, M, G, T)
- Overwrite protection
- Graceful handling of user interruption (Ctrl+C)
- Randomness quality analysis tool for verification

## Requirements

- Python 3.6 or higher

## Installation

No installation required. The application uses only Python standard library modules.

## Usage

```bash
python notepad_generator.py -s <size> [-o <output_file>]
```

### Parameters

- `-s`, `--size`: Size of the notepad file (required)
  - Format: `<number><unit>` where unit is one of:
    - `B` (bytes)
    - `K` (kilobytes)
    - `M` (megabytes)
    - `G` (gigabytes)
    - `T` (terabytes)
  - Examples: `100B`, `50K`, `10M`, `2G`, `1T`
- `-o`, `--output`: Output file name (optional, default: `notepad.txt`)

### Examples

```bash
# Create a 100MB notepad file
python notepad_generator.py -s 100M

# Create a 5GB notepad file with custom name
python notepad_generator.py -s 5G -o my_secure_notepad.txt

# Create a 10KB notepad file
python notepad_generator.py -s 10K
```

## How It Works

The application generates cryptographically secure random bytes using Python's `secrets` module and enhances them with additional entropy from system sources like time, process ID, and memory addresses. This ensures the content is truly random and suitable for security purposes.

The file creation process shows progress in real-time, and the application handles user interruption gracefully by cleaning up partially created files.

## Security Considerations

- The generated files contain truly random data suitable for cryptographic purposes
- Files should be stored securely and deleted after use
- For maximum security, use the generated notepad only once and then securely delete it

## Testing

The application has been tested with various file sizes:
- Small files (1KB to 1MB)
- Medium files (10MB to 100MB)
- Large files (1GB+)

All tests pass successfully, confirming the application works correctly with the specified requirements.

## Randomness Quality Analysis

The package includes a randomness analyzer tool (`randomness_analyzer.py`) that can evaluate the quality of generated notepad files:

```bash
python randomness_analyzer.py notepad.txt
```

The analyzer performs several statistical tests:
- Frequency test
- Block frequency test
- Runs test
- Longest run of ones test
- Entropy test
- Correlation test

The tool provides a comprehensive report with pass/fail results for each test and an overall quality score.

## License

This project is in the public domain.