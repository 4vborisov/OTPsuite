"""
Cross-platform GUI for One-Time Pad encryption and decryption.
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
import json

from otp_core import encrypt_data, decrypt_data, calculate_checksum, verify_checksum, xor_bytes
from otp_tracker import OTPTracker
from encoding import uuencode, uudecode, pack_metadata, unpack_metadata
from file_handler import read_file_chunks, write_file_chunks, get_file_size


class OTPEncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("One-Time Pad Encryption Tool")
        self.root.geometry("800x600")
        
        self.tracker = OTPTracker()
        self.current_otp_file = None
        self.current_offset = 0
        
        self.setup_ui()
    
    def setup_ui(self):
        # Main notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Text encryption tab
        self.text_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.text_frame, text="Text Encryption")
        self.setup_text_tab()
        
        # File encryption tab
        self.file_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.file_frame, text="File Encryption")
        self.setup_file_tab()
        
        # OTP management tab
        self.otp_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.otp_frame, text="OTP Management")
        self.setup_otp_tab()
    
    def setup_text_tab(self):
        # Text input
        ttk.Label(self.text_frame, text="Text to Encrypt/Decrypt:").pack(anchor=tk.W, pady=(10, 0))
        self.text_input = scrolledtext.ScrolledText(self.text_frame, height=8)
        self.text_input.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # OTP selection for text tab
        otp_frame = ttk.Frame(self.text_frame)
        otp_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(otp_frame, text="OTP File:").pack(side=tk.LEFT)
        self.text_otp_path = ttk.Entry(otp_frame, width=40)
        self.text_otp_path.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 5))
        ttk.Button(otp_frame, text="Browse...", command=self.browse_text_otp).pack(side=tk.LEFT)
        
        # Auto-detect OTP file option
        self.auto_detect_otp = tk.BooleanVar()
        auto_detect_frame = ttk.Frame(self.text_frame)
        auto_detect_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Checkbutton(auto_detect_frame, text="Auto-detect OTP file from message",
                       variable=self.auto_detect_otp).pack(anchor=tk.W)
        
        # Offset for text tab
        offset_frame = ttk.Frame(self.text_frame)
        offset_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(offset_frame, text="Offset:").pack(side=tk.LEFT)
        self.text_offset_entry = ttk.Entry(offset_frame, width=20)
        self.text_offset_entry.pack(side=tk.LEFT, padx=(5, 0))
        self.text_offset_entry.insert(0, "0")
        
        # Auto-detect offset option
        self.auto_detect_offset = tk.BooleanVar()
        auto_offset_frame = ttk.Frame(self.text_frame)
        auto_offset_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Checkbutton(auto_offset_frame, text="Auto-detect next free offset",
                       variable=self.auto_detect_offset,
                       command=self.toggle_offset_entry).pack(anchor=tk.W)
        
        # Controls
        controls_frame = ttk.Frame(self.text_frame)
        controls_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(controls_frame, text="Encrypt Text", command=self.encrypt_text).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(controls_frame, text="Decrypt Text", command=self.decrypt_text).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Copy to Clipboard", command=self.copy_to_clipboard).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(controls_frame, text="Paste from Clipboard", command=self.paste_from_clipboard).pack(side=tk.RIGHT, padx=5)
        
        # Result
        ttk.Label(self.text_frame, text="Result:").pack(anchor=tk.W, pady=(10, 0))
        self.text_result = scrolledtext.ScrolledText(self.text_frame, height=8)
        self.text_result.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
    
    def setup_file_tab(self):
        # File selection
        file_frame = ttk.Frame(self.file_frame)
        file_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(file_frame, text="File to Encrypt/Decrypt:").pack(anchor=tk.W)
        self.file_path = ttk.Entry(file_frame, width=50)
        self.file_path.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(file_frame, text="Browse...", command=self.browse_file).pack(side=tk.LEFT)
        
        # OTP selection
        otp_frame = ttk.Frame(self.file_frame)
        otp_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(otp_frame, text="OTP File:").pack(anchor=tk.W)
        self.otp_path = ttk.Entry(otp_frame, width=50)
        self.otp_path.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(otp_frame, text="Browse...", command=self.browse_otp).pack(side=tk.LEFT)
        
        # Auto-detect offset option
        self.file_auto_detect_offset = tk.BooleanVar()
        auto_offset_frame = ttk.Frame(self.file_frame)
        auto_offset_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Checkbutton(auto_offset_frame, text="Auto-detect next free offset",
                       variable=self.file_auto_detect_offset,
                       command=self.toggle_file_offset_entry).pack(anchor=tk.W)
        
        # Offset
        offset_frame = ttk.Frame(self.file_frame)
        offset_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(offset_frame, text="Offset:").pack(side=tk.LEFT)
        self.offset_entry = ttk.Entry(offset_frame, width=20)
        self.offset_entry.pack(side=tk.LEFT, padx=(5, 10))
        self.offset_entry.insert(0, "0")
        
        # Action buttons
        action_frame = ttk.Frame(self.file_frame)
        action_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(action_frame, text="Encrypt File", command=self.encrypt_file).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(action_frame, text="Decrypt File", command=self.decrypt_file).pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(self.file_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, padx=10, pady=5)
        
        # Status
        self.status_label = ttk.Label(self.file_frame, text="Ready")
        self.status_label.pack(fill=tk.X, padx=10, pady=5)
    
    def setup_otp_tab(self):
        # OTP file selection
        otp_select_frame = ttk.Frame(self.otp_frame)
        otp_select_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(otp_select_frame, text="OTP File:").pack(anchor=tk.W)
        self.otp_file_entry = ttk.Entry(otp_select_frame, width=50)
        self.otp_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(otp_select_frame, text="Browse...", command=self.browse_otp_for_info).pack(side=tk.LEFT)
        
        # Info display
        info_frame = ttk.Frame(self.otp_frame)
        info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        ttk.Label(info_frame, text="OTP Information:").pack(anchor=tk.W)
        self.otp_info = scrolledtext.ScrolledText(info_frame, height=15)
        self.otp_info.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Refresh button
        ttk.Button(info_frame, text="Refresh Info", command=self.show_otp_info).pack(anchor=tk.E)
    
    def browse_file(self):
        filename = filedialog.askopenfilename(title="Select file to encrypt/decrypt")
        if filename:
            self.file_path.delete(0, tk.END)
            self.file_path.insert(0, filename)
    
    def browse_otp(self):
        filename = filedialog.askopenfilename(title="Select OTP file")
        if filename:
            self.otp_path.delete(0, tk.END)
            self.otp_path.insert(0, filename)
    
    def browse_text_otp(self):
        filename = filedialog.askopenfilename(title="Select OTP file")
        if filename:
            self.text_otp_path.delete(0, tk.END)
            self.text_otp_path.insert(0, filename)
    
    def browse_otp_for_info(self):
        filename = filedialog.askopenfilename(title="Select OTP file")
        if filename:
            self.otp_file_entry.delete(0, tk.END)
            self.otp_file_entry.insert(0, filename)
            self.show_otp_info()
    
    def encrypt_text(self):
        try:
            text = self.text_input.get("1.0", tk.END).strip()
            if not text:
                messagebox.showwarning("Warning", "Please enter text to encrypt")
                return
            
            data = text.encode('utf-8')
            
            # Handle OTP file
            otp_file = None
            if self.auto_detect_otp.get():
                # For encryption, we can't auto-detect OTP file from message
                # User must select OTP file
                otp_file = self.text_otp_path.get().strip()
            else:
                otp_file = self.text_otp_path.get().strip()
            
            if not otp_file:
                messagebox.showwarning("Warning", "Please select an OTP file")
                return
            
            if not os.path.exists(otp_file):
                messagebox.showerror("Error", "OTP file does not exist")
                return
            
            # Handle offset
            if self.auto_detect_offset.get():
                offset = self.find_next_free_offset(os.path.basename(otp_file), len(data))
            else:
                offset = int(self.text_offset_entry.get() or 0)
            
            # Check if we can use this range
            if not self.tracker.can_use_range(os.path.basename(otp_file), offset, len(data)):
                messagebox.showwarning("Warning", "This OTP range has already been used for encryption!")
                return
            
            # Read OTP data
            with open(otp_file, 'rb') as f:
                f.seek(offset)
                pad = f.read(len(data))
            
            if len(pad) < len(data):
                messagebox.showerror("Error", "OTP file is too short for the text")
                return
            
            # Encrypt
            encrypted = encrypt_data(data, pad, 0)  # pad is already at correct offset
            
            # Calculate checksum
            checksum = calculate_checksum(data)
            
            # Pack metadata
            metadata = pack_metadata(os.path.basename(otp_file), offset, len(data), checksum)
            
            # Combine metadata and encrypted data
            payload = metadata + encrypted
            
            # Encode
            encoded = uuencode(payload)
            
            # Display result
            self.text_result.delete("1.0", tk.END)
            self.text_result.insert("1.0", encoded)
            
            # Record usage
            self.tracker.record_usage(os.path.basename(otp_file), offset, len(data), checksum)
            
            messagebox.showinfo("Success", f"Text encrypted successfully!\nUsed offset: {offset}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def decrypt_text(self):
        try:
            encoded_text = self.text_input.get("1.0", tk.END).strip()
            if not encoded_text:
                messagebox.showwarning("Warning", "Please enter encoded text to decrypt")
                return
            
            # Decode
            payload = uudecode(encoded_text)
            
            # Extract metadata
            try:
                otp_filename, offset, length, checksum = unpack_metadata(payload)
            except ValueError as e:
                messagebox.showerror("Error", f"Invalid metadata: {str(e)}")
                return
            
            # Get encrypted data
            # Calculate metadata size (simplified approach)
            metadata_size = 4 + len(otp_filename.encode('utf-8')) + 8 + 8 + 4 + len(checksum.encode('utf-8'))
            encrypted_data = payload[metadata_size:]
            
            # Find OTP file
            otp_file = None
            if self.auto_detect_otp.get():
                # Try to find OTP file automatically
                otp_file = self.find_otp_file(otp_filename)
            else:
                otp_file = self.text_otp_path.get().strip()
            
            if not otp_file:
                # Try to find it automatically if not specified
                otp_file = self.find_otp_file(otp_filename)
            
            if not otp_file:
                messagebox.showerror("Error", f"OTP file not found: {otp_filename}")
                return
            
            if not os.path.exists(otp_file):
                messagebox.showerror("Error", f"OTP file not found: {otp_file}")
                return
            
            # Check for overlap
            if self.tracker.check_overlap(os.path.basename(otp_file), offset, length):
                messagebox.showwarning("Warning", "This OTP range overlaps with a previously used range!")
            
            # Read OTP data
            with open(otp_file, 'rb') as f:
                f.seek(offset)
                pad = f.read(length)
            
            if len(pad) < length:
                messagebox.showerror("Error", "OTP file is too short for the encrypted data")
                return
            
            # Decrypt
            decrypted = decrypt_data(encrypted_data, pad, 0)  # pad is already at correct offset
            
            # Verify checksum
            if not verify_checksum(decrypted, checksum):
                messagebox.showerror("Error", "Data integrity check failed!")
                return
            
            # Display result
            self.text_result.delete("1.0", tk.END)
            self.text_result.insert("1.0", decrypted.decode('utf-8'))
            
            messagebox.showinfo("Success", "Text decrypted successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    
    def encrypt_file(self):
        # Run in separate thread to keep GUI responsive
        threading.Thread(target=self._encrypt_file_thread, daemon=True).start()
    
    def _encrypt_file_thread(self):
        try:
            self.root.after(0, lambda: self.status_label.config(text="Encrypting file..."))
            self.root.after(0, lambda: self.progress.start())
            
            file_path = self.file_path.get().strip()
            if not file_path:
                self.root.after(0, lambda: messagebox.showwarning("Warning", "Please select a file to encrypt"))
                return
            
            if not os.path.exists(file_path):
                self.root.after(0, lambda: messagebox.showerror("Error", "File does not exist"))
                return
            
            file_size = get_file_size(file_path)
            
            otp_file = self.otp_path.get().strip()
            if not otp_file:
                self.root.after(0, lambda: messagebox.showwarning("Warning", "Please select an OTP file"))
                return
            
            if not os.path.exists(otp_file):
                self.root.after(0, lambda: messagebox.showerror("Error", "OTP file does not exist"))
                return
            
            # Handle offset
            if self.file_auto_detect_offset.get():
                offset = self.find_next_free_offset(os.path.basename(otp_file), file_size)
            else:
                offset = int(self.offset_entry.get() or 0)
            
            # Check if we can use this range
            if not self.tracker.can_use_range(os.path.basename(otp_file), offset, file_size):
                self.root.after(0, lambda: messagebox.showwarning("Warning", "This OTP range has already been used for encryption!"))
                return
            
            # Read entire file
            with open(file_path, 'rb') as infile:
                file_data = infile.read()
            
            # For simplicity, we'll read the entire OTP segment at once
            # In a more robust implementation, we'd handle this in chunks too
            with open(otp_file, 'rb') as otp_f:
                otp_f.seek(offset)
                pad_data = otp_f.read(file_size)
            
            if len(pad_data) < file_size:
                self.root.after(0, lambda: messagebox.showerror("Error", "OTP file is too short for the file"))
                return
            
            # Encrypt data
            encrypted_data = xor_bytes(file_data, pad_data)
            
            # Calculate checksum
            checksum = calculate_checksum(file_data)
            
            # Pack metadata
            metadata = pack_metadata(os.path.basename(otp_file), offset, file_size, checksum)
            
            # Combine metadata and encrypted data
            payload = metadata + encrypted_data
            
            # Encode with uuencode
            encoded_payload = uuencode(payload)
            
            # Save encrypted file
            output_file = file_path + ".encrypted"
            with open(output_file, 'w') as outfile:
                outfile.write(encoded_payload)
            
            # Record usage
            self.tracker.record_usage(os.path.basename(otp_file), offset, file_size, checksum)
            
            self.root.after(0, lambda: messagebox.showinfo("Success", f"File encrypted successfully!\nSaved as: {output_file}\nUsed offset: {offset}"))
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"File encryption failed: {str(e)}"))
        finally:
            self.root.after(0, lambda: self.progress.stop())
            self.root.after(0, lambda: self.status_label.config(text="Ready"))
    
    def decrypt_file(self):
        # Run in separate thread to keep GUI responsive
        threading.Thread(target=self._decrypt_file_thread, daemon=True).start()
    
    def _decrypt_file_thread(self):
        try:
            self.root.after(0, lambda: self.status_label.config(text="Decrypting file..."))
            self.root.after(0, lambda: self.progress.start())
            
            file_path = self.file_path.get().strip()
            if not file_path:
                self.root.after(0, lambda: messagebox.showwarning("Warning", "Please select a file to decrypt"))
                return
            
            if not os.path.exists(file_path):
                self.root.after(0, lambda: messagebox.showerror("Error", "File does not exist"))
                return
            
            # Read the entire encrypted file
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Extract metadata (first try to decode if it's uuencoded)
            try:
                # Try to decode as uuencoded data
                decoded_data = uudecode(file_data.decode('ascii'))
                # Extract metadata from decoded data
                otp_filename, offset, length, checksum = unpack_metadata(decoded_data)
                # Extract encrypted data
                metadata_size = 4 + len(otp_filename.encode('utf-8')) + 8 + 8 + 4 + len(checksum.encode('utf-8'))
                encrypted_data = decoded_data[metadata_size:metadata_size + length]
            except:
                # Assume it's raw encrypted data with embedded metadata
                try:
                    otp_filename, offset, length, checksum = unpack_metadata(file_data)
                    # Extract encrypted data
                    metadata_size = 4 + len(otp_filename.encode('utf-8')) + 8 + 8 + 4 + len(checksum.encode('utf-8'))
                    encrypted_data = file_data[metadata_size:metadata_size + length]
                except:
                    # Fallback to raw data
                    encrypted_data = file_data
                    # Try to get OTP file and offset from GUI
                    otp_filename = None
                    offset = 0
                    length = len(encrypted_data)
            
            # Find OTP file
            otp_file = self.otp_path.get().strip()
            if not otp_file and otp_filename:
                # Try to find OTP file automatically
                otp_file = self.find_otp_file(otp_filename)
            
            if not otp_file:
                self.root.after(0, lambda: messagebox.showwarning("Warning", "Please select an OTP file"))
                return
            
            if not os.path.exists(otp_file):
                self.root.after(0, lambda: messagebox.showerror("Error", "OTP file does not exist"))
                return
            
            # Read OTP data
            with open(otp_file, 'rb') as otp_f:
                otp_f.seek(offset)
                pad_data = otp_f.read(length)
            
            if len(pad_data) < length:
                self.root.after(0, lambda: messagebox.showerror("Error", "OTP file is too short for the encrypted data"))
                return
            
            # Decrypt data
            decrypted_data = xor_bytes(encrypted_data, pad_data)
            
            # Save decrypted file with original extension
            if file_path.endswith('.encrypted'):
                output_file = file_path[:-10]  # Remove .encrypted extension
            else:
                # Try to extract original filename from metadata
                original_filename = otp_filename if otp_filename and otp_filename != os.path.basename(otp_file) else None
                if original_filename and not file_path.endswith('.encrypted'):
                    output_file = file_path + "_decrypted"
                else:
                    output_file = file_path + ".decrypted"
            
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)
            
            self.root.after(0, lambda: messagebox.showinfo("Success", f"File decrypted successfully!\nSaved as: {output_file}"))
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"File decryption failed: {str(e)}"))
        finally:
            self.root.after(0, lambda: self.progress.stop())
            self.root.after(0, lambda: self.status_label.config(text="Ready"))
    
    def show_otp_info(self):
        try:
            otp_file = self.otp_file_entry.get().strip()
            if not otp_file:
                messagebox.showwarning("Warning", "Please select an OTP file")
                return
            
            if not os.path.exists(otp_file):
                messagebox.showerror("Error", "OTP file does not exist")
                return
            
            # Get file info
            file_size = get_file_size(otp_file)
            base_name = os.path.basename(otp_file)
            
            # Get usage info
            used_ranges = self.tracker.get_used_ranges(base_name)
            
            # Format info
            info = f"OTP File: {otp_file}\n"
            info += f"Size: {file_size} bytes\n"
            info += f"Used Ranges: {len(used_ranges)}\n\n"
            
            if used_ranges:
                info += "Used Ranges:\n"
                for i, range_obj in enumerate(used_ranges):
                    info += f"  {i+1}. {range_obj.start} - {range_obj.end} ({range_obj.end - range_obj.start} bytes)\n"
            else:
                info += "No ranges have been used yet.\n"
            
            self.otp_info.delete("1.0", tk.END)
            self.otp_info.insert("1.0", info)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get OTP info: {str(e)}")
    
    def copy_to_clipboard(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.text_result.get("1.0", tk.END))
        messagebox.showinfo("Success", "Text copied to clipboard!")
    
    def paste_from_clipboard(self):
        try:
            text = self.root.clipboard_get()
            self.text_input.delete("1.0", tk.END)
            self.text_input.insert("1.0", text)
        except tk.TclError:
            messagebox.showwarning("Warning", "Clipboard is empty or contains non-text data")
    
    def toggle_offset_entry(self):
        """Enable/disable offset entry based on auto-detect checkbox."""
        if self.auto_detect_offset.get():
            self.text_offset_entry.config(state="disabled")
        else:
            self.text_offset_entry.config(state="normal")
    
    def toggle_file_offset_entry(self):
        """Enable/disable file offset entry based on auto-detect checkbox."""
        if self.file_auto_detect_offset.get():
            self.offset_entry.config(state="disabled")
        else:
            self.offset_entry.config(state="normal")
    
    def find_otp_file(self, otp_filename):
        """
        Try to find an OTP file by name in common locations.
        
        Args:
            otp_filename: Name of the OTP file to find
            
        Returns:
            Full path to the OTP file or None if not found
        """
        # Check current directory
        if os.path.exists(otp_filename):
            return otp_filename
        
        # Check in common subdirectories
        for directory in ["otp", "pads", "keys"]:
            filepath = os.path.join(directory, otp_filename)
            if os.path.exists(filepath):
                return filepath
        
        # Check in parent directory
        parent_filepath = os.path.join("..", otp_filename)
        if os.path.exists(parent_filepath):
            return parent_filepath
        
        return None
    
    def find_next_free_offset(self, otp_filename, data_length):
        """
        Find the next free offset in an OTP file.
        
        Args:
            otp_filename: Name of the OTP file
            data_length: Length of data to be encrypted
            
        Returns:
            Next free offset or 0 if none found
        """
        used_ranges = self.tracker.get_used_ranges(otp_filename)
        
        if not used_ranges:
            return 0
        
        # Sort ranges by start position
        used_ranges.sort(key=lambda r: r.start)
        
        # Find the first gap large enough
        current_end = 0
        for range_obj in used_ranges:
            if range_obj.start >= current_end + data_length:
                return current_end
            current_end = max(current_end, range_obj.end)
        
        # No gap found, use end of last range
        return current_end


def main():
    root = tk.Tk()
    app = OTPEncryptionApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()