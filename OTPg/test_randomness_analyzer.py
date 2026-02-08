#!/usr/bin/env python3
"""
Test suite for the One-Time Notepad Randomness Analyzer
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class TestRandomnessAnalyzer(unittest.TestCase):
    """Test cases for the randomness analyzer application."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.script_path = Path("randomness_analyzer.py")
        self.generator_path = Path("notepad_generator.py")
        
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
        self.assertTrue(self.script_path.exists(), "randomness_analyzer.py should exist")
    
    def test_help_output(self):
        """Test that help output is displayed correctly."""
        result = subprocess.run(
            [sys.executable, str(self.script_path), "--help"],
            capture_output=True,
            text=True
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("One-Time Notepad Randomness Quality Analyzer", result.stdout)
    
    def test_analysis_with_nonexistent_file(self):
        """Test analysis with nonexistent file."""
        nonexistent_file = self.test_dir / "nonexistent.txt"
        result = subprocess.run(
            [sys.executable, str(self.script_path), str(nonexistent_file)],
            capture_output=True,
            text=True
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Error: File", result.stdout)
    
    def test_analysis_with_small_file(self):
        """Test analysis with a small generated file."""
        # First create a small test file
        output_file = self.test_dir / "test_notepad.txt"
        gen_result = subprocess.run(
            [sys.executable, str(self.generator_path), "-s", "10K", "-o", str(output_file)],
            input="y\n",  # Confirm overwrite if needed
            capture_output=True,
            text=True
        )
        
        # Check that the file was created
        self.assertEqual(gen_result.returncode, 0, f"Generator failed: {gen_result.stderr}")
        self.assertTrue(output_file.exists(), "Output file should be created")
        
        # Now analyze the file
        result = subprocess.run(
            [sys.executable, str(self.script_path), str(output_file)],
            capture_output=True,
            text=True
        )
        
        # Check that the analysis completed
        self.assertEqual(result.returncode, 0, f"Analyzer failed: {result.stderr}")
        self.assertIn("Analyzing randomness quality", result.stdout)
        self.assertIn("File size:", result.stdout)
    
    def test_analysis_with_medium_file(self):
        """Test analysis with a medium generated file."""
        # First create a medium test file
        output_file = self.test_dir / "medium_notepad.txt"
        gen_result = subprocess.run(
            [sys.executable, str(self.generator_path), "-s", "1M", "-o", str(output_file)],
            input="y\n",  # Confirm overwrite if needed
            capture_output=True,
            text=True
        )
        
        # Check that the file was created
        self.assertEqual(gen_result.returncode, 0, f"Generator failed: {gen_result.stderr}")
        self.assertTrue(output_file.exists(), "Output file should be created")
        
        # Now analyze the file
        result = subprocess.run(
            [sys.executable, str(self.script_path), str(output_file)],
            capture_output=True,
            text=True
        )
        
        # Check that the analysis completed
        self.assertEqual(result.returncode, 0, f"Analyzer failed: {result.stderr}")
        self.assertIn("Analyzing randomness quality", result.stdout)
        self.assertIn("File size:", result.stdout)


if __name__ == "__main__":
    unittest.main()