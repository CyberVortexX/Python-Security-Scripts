# hash_checker.py
import hashlib
import os

def calculate_hash(filepath):
    """Calculates the SHA-256 hash of a file."""
    # Check if the file exists
    if not os.path.exists(filepath):
        return None

    sha256_hash = hashlib.sha256()
    try:
        # Open the file in binary read mode
        with open(filepath, "rb") as f:
            # Read and update hash string chunk by chunk
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error reading file: {e}")
        return None

def main():
    """Main function to run the hash checker."""
    print("--- File Integrity Checker (SHA-256) ---")
    filepath = input("Enter the file path to hash: ")

    file_hash = calculate_hash(filepath)

    if file_hash:
        print(f"\n✅ Successfully generated hash.")
        print(f"File: {os.path.basename(filepath)}")
        print(f"SHA-256 Hash: {file_hash}")
    else:
        print(f"\n❌ Error: File '{filepath}' not found or could not be read.")

if __name__ == "__main__":
    main()
