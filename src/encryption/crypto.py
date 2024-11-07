from cryptography.fernet import Fernet
import os
import logging
import json
from datetime import datetime

class FileEncryption:
    def __init__(self, target_dir, key_file="encryption_key.key"):
        """Initialize encryption module with target directory"""
        self.target_dir = target_dir
        self.key_file = key_file
        self.encrypted_files = []
        self.key = None
        
        # Setup logging
        logging.basicConfig(
            filename='encryption_log.txt',
            level=logging.INFO,
            format='%(asctime)s - %(message)s'
        )

    def generate_key(self):
        """Generate encryption key"""
        self.key = Fernet.generate_key()
        # Save key for demonstration/educational purposes
        with open(self.key_file, 'wb') as key_file:
            key_file.write(self.key)
        return self.key

    def load_key(self):
        """Load existing key if available"""
        try:
            with open(self.key_file, 'rb') as key_file:
                self.key = key_file.read()
            return self.key
        except FileNotFoundError:
            return self.generate_key()

    def encrypt_file(self, file_path):
        """Encrypt a single file"""
        try:
            if self.key is None:
                self.load_key()
            
            fernet = Fernet(self.key)
            
            # Read file content
            with open(file_path, 'rb') as file:
                file_data = file.read()
            
            # Encrypt data
            encrypted_data = fernet.encrypt(file_data)
            
            # Write encrypted data
            encrypted_file_path = file_path + '.encrypted'
            with open(encrypted_file_path, 'wb') as encrypted_file:
                encrypted_file.write(encrypted_data)
            
            # Log encryption
            self.encrypted_files.append({
                'original_path': file_path,
                'encrypted_path': encrypted_file_path,
                'timestamp': str(datetime.now())
            })
            
            logging.info(f"Encrypted: {file_path}")
            return True
            
        except Exception as e:
            logging.error(f"Encryption failed for {file_path}: {str(e)}")
            return False

    def decrypt_file(self, encrypted_file_path):
        """Decrypt a single file"""
        try:
            if self.key is None:
                self.load_key()
                
            fernet = Fernet(self.key)
            
            # Read encrypted data
            with open(encrypted_file_path, 'rb') as enc_file:
                encrypted_data = enc_file.read()
            
            # Decrypt data
            decrypted_data = fernet.decrypt(encrypted_data)
            
            # Write decrypted data
            original_path = encrypted_file_path.replace('.encrypted', '')
            with open(original_path, 'wb') as dec_file:
                dec_file.write(decrypted_data)
            
            logging.info(f"Decrypted: {encrypted_file_path}")
            return True
            
        except Exception as e:
            logging.error(f"Decryption failed for {encrypted_file_path}: {str(e)}")
            return False

    def encrypt_directory(self):
        """Encrypt all files in target directory"""
        try:
            for root, _, files in os.walk(self.target_dir):
                for file in files:
                    # Skip already encrypted files
                    if file.endswith('.encrypted'):
                        continue
                    
                    file_path = os.path.join(root, file)
                    self.encrypt_file(file_path)
            
            # Save encryption record
            self.save_encryption_record()
            return True
            
        except Exception as e:
            logging.error(f"Directory encryption failed: {str(e)}")
            return False

    def decrypt_directory(self):
        """Decrypt all encrypted files in target directory"""
        try:
            for root, _, files in os.walk(self.target_dir):
                for file in files:
                    if file.endswith('.encrypted'):
                        file_path = os.path.join(root, file)
                        self.decrypt_file(file_path)
            return True
            
        except Exception as e:
            logging.error(f"Directory decryption failed: {str(e)}")
            return False

    def save_encryption_record(self):
        """Save record of encrypted files"""
        record = {
            'encryption_time': str(datetime.now()),
            'target_directory': self.target_dir,
            'encrypted_files': self.encrypted_files
        }
        
        with open('encryption_record.json', 'w') as record_file:
            json.dump(record, record_file, indent=4)