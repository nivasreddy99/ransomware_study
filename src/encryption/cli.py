import argparse
from crypto import FileEncryption
import os

def main():
    parser = argparse.ArgumentParser(description='File Encryption Tool for Educational Purposes')
    parser.add_argument('--dir', type=str, required=True, help='Directory to encrypt/decrypt')
    parser.add_argument('--action', type=str, choices=['encrypt', 'decrypt'], required=True,
                      help='Action to perform: encrypt or decrypt')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.dir):
        print(f"Directory not found: {args.dir}")
        return
    
    encryptor = FileEncryption(args.dir)
    
    if args.action == 'encrypt':
        print(f"Encrypting directory: {args.dir}")
        if encryptor.encrypt_directory():
            print("Encryption completed successfully")
        else:
            print("Encryption failed")
    else:
        print(f"Decrypting directory: {args.dir}")
        if encryptor.decrypt_directory():
            print("Decryption completed successfully")
        else:
            print("Decryption failed")

if __name__ == "__main__":
    main()