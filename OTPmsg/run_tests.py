"""
Simple script to run all tests.
"""
import subprocess
import sys


def run_tests():
    """Run the test suite."""
    print("Running tests...")
    try:
        result = subprocess.run([sys.executable, "-m", "pytest", "tests", "-v"], 
                                capture_output=True, text=True, cwd=".")
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        print(f"Tests completed with return code: {result.returncode}")
        return result.returncode == 0
    except Exception as e:
        print(f"Error running tests: {e}")
        return False


if __name__ == "__main__":
    success = run_tests()
    if success:
        print("All tests passed!")
    else:
        print("Some tests failed!")
        sys.exit(1)