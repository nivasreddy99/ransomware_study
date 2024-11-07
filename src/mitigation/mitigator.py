import os
import shutil
import psutil
import logging
import json
from datetime import datetime
import threading
import time

class RansomwareMitigator:
    def __init__(self, protected_paths, backup_dir):
        self.protected_paths = protected_paths
        self.backup_dir = backup_dir
        self.backup_interval = 3600  # 1 hour
        self.max_backups = 5
        self.is_running = True
        
        # Configure logging
        logging.basicConfig(
            filename='mitigation.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Initialize backup thread
        self.backup_thread = threading.Thread(target=self._backup_loop)
        self.backup_thread.daemon = True
        self.backup_thread.start()

    def _backup_loop(self):
        """Continuous backup loop"""
        while self.is_running:
            self.create_backup()
            time.sleep(self.backup_interval)

    def create_backup(self):
        """Create backup of protected directories"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_path = os.path.join(self.backup_dir, f'backup_{timestamp}')
            
            for protected_path in self.protected_paths:
                if not os.path.exists(protected_path):
                    continue
                    
                dest_path = os.path.join(backup_path, os.path.basename(protected_path))
                shutil.copytree(protected_path, dest_path)
            
            self._cleanup_old_backups()
            self._save_backup_metadata(backup_path, timestamp)
            
            logging.info(f"Backup created successfully: {backup_path}")
            return backup_path
            
        except Exception as e:
            logging.error(f"Backup creation failed: {str(e)}")
            return None

    def _cleanup_old_backups(self):
        """Remove old backups exceeding max_backups"""
        try:
            backups = []
            for item in os.listdir(self.backup_dir):
                if item.startswith('backup_'):
                    path = os.path.join(self.backup_dir, item)
                    backups.append((os.path.getmtime(path), path))
            
            # Sort by modification time
            backups.sort(reverse=True)
            
            # Remove excess backups
            for _, path in backups[self.max_backups:]:
                shutil.rmtree(path)
                logging.info(f"Removed old backup: {path}")
                
        except Exception as e:
            logging.error(f"Backup cleanup failed: {str(e)}")

    def restore_from_backup(self, backup_timestamp=None):
        """Restore files from backup"""
        try:
            if backup_timestamp is None:
                # Get most recent backup
                backups = [d for d in os.listdir(self.backup_dir) if d.startswith('backup_')]
                if not backups:
                    raise Exception("No backups found")
                backup_timestamp = max(backups)

            backup_path = os.path.join(self.backup_dir, backup_timestamp)
            
            # Restore each protected directory
            for protected_path in self.protected_paths:
                source_path = os.path.join(backup_path, os.path.basename(protected_path))
                if os.path.exists(protected_path):
                    shutil.rmtree(protected_path)
                shutil.copytree(source_path, protected_path)
            
            logging.info(f"Restored from backup: {backup_timestamp}")
            return True
            
        except Exception as e:
            logging.error(f"Restore failed: {str(e)}")
            return False

    def terminate_suspicious_processes(self, suspicious_pids):
        """Terminate processes identified as suspicious"""
        for pid in suspicious_pids:
            try:
                process = psutil.Process(pid)
                process.terminate()
                logging.info(f"Terminated suspicious process: {pid}")
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                logging.error(f"Failed to terminate process {pid}: {str(e)}")

    def _save_backup_metadata(self, backup_path, timestamp):
        """Save metadata about the backup"""
        metadata = {
            'timestamp': timestamp,
            'backup_path': backup_path,
            'protected_paths': self.protected_paths,
            'creation_time': str(datetime.now())
        }
        
        metadata_path = os.path.join(backup_path, 'backup_metadata.json')
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=4)

    def stop_service(self):
        """Stop the backup service"""
        self.is_running = False
        self.backup_thread.join()