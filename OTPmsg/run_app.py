"""
Script to run the OTP Encryption Tool GUI application.
"""
import sys
import os


def main():
    """Run the OTP Encryption Tool GUI application."""
    try:
        # Import the GUI module
        from otp_gui import main as gui_main
        
        # Run the GUI application
        gui_main()
        
    except ImportError as e:
        print(f"Error importing GUI module: {e}")
        print("Make sure all required modules are installed.")
        print("Try running: pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        print(f"Error running the application: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()