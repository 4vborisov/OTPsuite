#!/usr/bin/env python3
"""
Test suite for the One-Time Notepad Generator
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class TestNotepadGenerator(unittest.TestCase):
    """Test cases for the notepad generator application."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.script_path = Path("notepad_generator.py")
        
    def tearDown(self):
        """Clean up test environment."""
        # Remove test files
        for file_path in self.test_dir.glob("*"):
            try:
                file_path.unlink()
            except OSError:
                pass
        # Remove test directory
        try:
            self.test_dir.rmdir()
        except OSError:
            pass
    
    def test_script_exists(self):
        """Test that the script exists."""
        self.assertTrue(self.script_path.exists(), "notepad_generator.py should exist")
    
    def test_help_output(self):
        """Test that help output is displayed correctly."""
        result = subprocess.run(
            [sys.executable, str(self.script_path), "--help"],
            capture_output=True,
            text=True
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("One-Time Notepad Generator", result.stdout)
    
    def test_invalid_size_format(self):
        """Test handling of invalid size format."""
        result = subprocess.run(
            [sys.executable, str(self.script_path), "-s", "invalid"],
            capture_output=True,
            text=True
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Error", result.stderr)
    
    def test_small_file_creation(self):
        """Test creation of a small file."""
        output_file = self.test_dir / "small_notepad.txt"
        result = subprocess.run(
            [sys.executable, str(self.script_path), "-s", "10K", "-o", str(output_file)],
            input="y\n",  # Confirm overwrite if needed
            capture_output=True,
            text=True
        )
        
        # Check that the command executed successfully
        self.assertEqual(result.returncode, 0, f"Script failed with error: {result.stderr}")
        
        # Check that the file was created
        self.assertTrue(output_file.exists(), "Output file should be created")
        
        # Check file size
        file_size = output_file.stat().st_size
        self.assertEqual(file_size, 10 * 1024, f"File size should be 10KB, got {file_size} bytes")
    
    def test_medium_file_creation(self):
        """Test creation of a medium file."""
        output_file = self.test_dir / "medium_notepad.txt"
        result = subprocess.run(
            [sys.executable, str(self.script_path), "-s", "1M", "-o", str(output_file)],
            input="y\n",  # Confirm overwrite if needed
            capture_output=True,
            text=True
        )
        
        # Check that the command executed successfully
        self.assertEqual(result.returncode, 0, f"Script failed with error: {result.stderr}")
        
        # Check that the file was created
        self.assertTrue(output_file.exists(), "Output file should be created")
        
        # Check file size
        file_size = output_file.stat().st_size
        self.assertEqual(file_size, 1024 * 1024, f"File size should be 1MB, got {file_size} bytes")
    
    def test_size_parsing(self):
        """Test size parsing function."""
        # Import the function directly
        import importlib.util
        spec = importlib.util.spec_from_file_location("notepad_generator", self.script_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        # Test various size formats
        test_cases = [
            ("1B", 1),
            ("1K", 1024),
            ("1M", 1024**2),
            ("1G", 1024**3),
            ("1T", 1024**4),
            ("500B", 500),
            ("2.5K", int(2.5 * 1024)),
            ("0.5M", int(0.5 * 1024**2)),
        ]
        
        for size_str, expected_bytes in test_cases:
            with self.subTest(size_str=size_str):
                parsed_size = module.parse_size(size_str)
                self.assertEqual(parsed_size, expected_bytes, 
                               f"Size parsing failed for {size_str}")
    
    def test_invalid_sizes(self):
        """Test handling of invalid sizes."""
        # Import the function directly
        import importlib.util
        spec = importlib.util.spec_from_file_location("notepad_generator", self.script_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        # Test invalid sizes
        invalid_sizes = ["", "invalid", "-10K", "10X"]
        
        for invalid_size in invalid_sizes:
            with self.subTest(invalid_size=invalid_size):
                with self.assertRaises(ValueError):
                    module.parse_size(invalid_size)


if __name__ == "__main__":
    unittest.main()