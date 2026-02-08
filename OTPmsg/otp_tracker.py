"""
OTP usage tracking to prevent reuse.
"""
import json
import os
from typing import List, Tuple, Dict, Any


class Range:
    """Represents a range of bytes in an OTP file."""
    
    def __init__(self, start: int, end: int):
        """
        Initialize a range.
        
        Args:
            start: Start position (inclusive)
            end: End position (exclusive)
        """
        self.start = start
        self.end = end
    
    def overlaps(self, other: 'Range') -> bool:
        """
        Check if this range overlaps with another range.
        
        Args:
            other: Another range to check
            
        Returns:
            True if ranges overlap, False otherwise
        """
        return self.start < other.end and self.end > other.start
    
    def __repr__(self):
        return f"Range({self.start}, {self.end})"


class OTPTracker:
    """Tracks OTP usage to prevent reuse."""
    
    def __init__(self, metadata_file: str = "otp_usage.json"):
        """
        Initialize the tracker.
        
        Args:
            metadata_file: Path to the metadata file
        """
        self.metadata_file = metadata_file
        self.usage_data = self._load_usage_data()
    
    def _load_usage_data(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Load usage data from the metadata file.
        
        Returns:
            Dictionary mapping OTP filenames to lists of used ranges
        """
        if os.path.exists(self.metadata_file):
            try:
                with open(self.metadata_file, 'r') as f:
                    data = json.load(f)
                    # Convert to Range objects
                    for filename in data:
                        for entry in data[filename]:
                            entry['range'] = Range(entry['range']['start'], entry['range']['end'])
                    return data
            except (json.JSONDecodeError, KeyError):
                # If file is corrupted, start fresh
                return {}
        return {}
    
    def _save_usage_data(self):
        """Save usage data to the metadata file."""
        # Convert Range objects to dictionaries for JSON serialization
        serializable_data = {}
        for filename, entries in self.usage_data.items():
            serializable_data[filename] = [
                {
                    'range': {'start': entry['range'].start, 'end': entry['range'].end},
                    'checksum': entry['checksum']
                }
                for entry in entries
            ]
        
        with open(self.metadata_file, 'w') as f:
            json.dump(serializable_data, f, indent=2)
    
    def get_used_ranges(self, otp_filename: str) -> List[Range]:
        """
        Get all used ranges for an OTP file.
        
        Args:
            otp_filename: Name of the OTP file
            
        Returns:
            List of used ranges
        """
        if otp_filename not in self.usage_data:
            return []
        
        return [entry['range'] for entry in self.usage_data[otp_filename]]
    
    def check_overlap(self, otp_filename: str, start: int, length: int) -> bool:
        """
        Check if a range overlaps with any used ranges.
        
        Args:
            otp_filename: Name of the OTP file
            start: Start position
            length: Length of the range
            
        Returns:
            True if overlap detected, False otherwise
        """
        new_range = Range(start, start + length)
        used_ranges = self.get_used_ranges(otp_filename)
        
        return any(new_range.overlaps(used_range) for used_range in used_ranges)
    
    def record_usage(self, otp_filename: str, start: int, length: int, checksum: str):
        """
        Record usage of an OTP range.
        
        Args:
            otp_filename: Name of the OTP file
            start: Start position
            length: Length of the range
            checksum: Checksum of the encrypted data
        """
        end = start + length
        
        if otp_filename not in self.usage_data:
            self.usage_data[otp_filename] = []
        
        self.usage_data[otp_filename].append({
            'range': Range(start, end),
            'checksum': checksum
        })
        
        self._save_usage_data()
    
    def can_use_range(self, otp_filename: str, start: int, length: int) -> bool:
        """
        Check if a range can be used for encryption (no overlaps).
        
        Args:
            otp_filename: Name of the OTP file
            start: Start position
            length: Length of the range
            
        Returns:
            True if range can be used, False otherwise
        """
        return not self.check_overlap(otp_filename, start, length)