"""
Tests for the OTP tracker module.
"""
import os
import tempfile
import pytest

from otp_tracker import OTPTracker, Range


def test_range_overlaps():
    """Test range overlap detection."""
    # Non-overlapping ranges
    r1 = Range(0, 10)
    r2 = Range(15, 20)
    assert not r1.overlaps(r2)
    
    # Overlapping ranges
    r3 = Range(5, 15)
    assert r1.overlaps(r3)
    
    # Adjacent ranges (should not overlap)
    r4 = Range(10, 15)
    assert not r1.overlaps(r4)
    
    # Contained ranges
    r5 = Range(2, 8)
    assert r1.overlaps(r5)


def test_tracker_can_use_range():
    """Test range usage checking."""
    with tempfile.TemporaryDirectory() as temp_dir:
        metadata_file = os.path.join(temp_dir, "test_usage.json")
        tracker = OTPTracker(metadata_file)
        
        otp_filename = "test.pad"
        
        # Should be able to use range initially
        assert tracker.can_use_range(otp_filename, 0, 100)
        
        # Record usage
        tracker.record_usage(otp_filename, 0, 100, "checksum")
        
        # Should not be able to use overlapping range
        assert not tracker.can_use_range(otp_filename, 50, 100)
        
        # Should be able to use non-overlapping range
        assert tracker.can_use_range(otp_filename, 200, 100)


def test_tracker_persistence():
    """Test tracker persistence."""
    with tempfile.TemporaryDirectory() as temp_dir:
        metadata_file = os.path.join(temp_dir, "test_usage.json")
        
        # Create tracker and record usage
        tracker1 = OTPTracker(metadata_file)
        tracker1.record_usage("test.pad", 0, 100, "checksum")
        
        # Create new tracker instance
        tracker2 = OTPTracker(metadata_file)
        
        # Should detect overlap
        assert not tracker2.can_use_range("test.pad", 50, 100)