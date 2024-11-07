import psutil
import os
import logging
import time
from collections import defaultdict
from datetime import datetime
import threading

class RansomwareDetector:
    def __init__(self, monitored_paths):
        self.monitored_paths = monitored_paths
        self.file_operations = defaultdict(int)
        self.suspicious_processes = set()
        self.operation_threshold = 10  # File operations per second
        self.extension_blacklist = {'.encrypted', '.locked', '.crypto', '.pay', '.ransom'}
        self.suspicious_patterns = defaultdict(int)
        
        # Configure logging
        logging.basicConfig(
            filename='detection.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Start monitoring thread
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def _monitor_loop(self):
        """Continuous monitoring loop"""
        while self.is_monitoring:
            self._check_processes()
            self._check_file_operations()
            time.sleep(1)  # Check every second

    def _check_processes(self):
        """Monitor system processes for suspicious behavior"""
        for proc in psutil.process_iter(['pid', 'name', 'io_counters']):
            try:
                # Check I/O operations
                io_counters = proc.io_counters()
                if io_counters.write_bytes > 1000000:  # High write activity
                    self.suspicious_processes.add(proc.pid)
                    logging.warning(f"Suspicious I/O activity detected - PID: {proc.pid}, Name: {proc.name()}")

                # Check file handles
                open_files = proc.open_files()
                if len(open_files) > 50:  # Many open files
                    self.suspicious_processes.add(proc.pid)
                    logging.warning(f"High number of open files detected - PID: {proc.pid}, Name: {proc.name()}")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _check_file_operations(self):
        """Check for suspicious file operations"""
        current_time = time.time()
        for path in self.monitored_paths:
            if not os.path.exists(path):
                continue

            for root, _, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    _, ext = os.path.splitext(file)
                    
                    # Check for suspicious extensions
                    if ext in self.extension_blacklist:
                        self.suspicious_patterns['suspicious_extensions'] += 1
                        logging.warning(f"Suspicious file extension detected: {file_path}")

                    # Check file modification times
                    try:
                        mtime = os.path.getmtime(file_path)
                        if current_time - mtime < 1:  # Modified in last second
                            self.file_operations[current_time] += 1
                    except OSError:
                        continue

        # Check operation rate
        recent_ops = sum(count for timestamp, count in self.file_operations.items() 
                        if current_time - timestamp < 1)
        if recent_ops > self.operation_threshold:
            logging.warning(f"High file operation rate detected: {recent_ops} ops/sec")
            return True
        return False

    def get_threat_score(self):
        """Calculate current threat score based on various indicators"""
        score = 0
        
        # Check file operations
        if len(self.file_operations) > self.operation_threshold:
            score += 30
        
        # Check suspicious processes
        if self.suspicious_processes:
            score += 20
        
        # Check suspicious extensions
        if self.suspicious_patterns['suspicious_extensions'] > 0:
            score += 25
        
        # High I/O operations
        if any(self.file_operations.values()):
            score += 15
        
        return score

    def stop_monitoring(self):
        """Stop the monitoring thread"""
        self.is_monitoring = False
        self.monitor_thread.join()