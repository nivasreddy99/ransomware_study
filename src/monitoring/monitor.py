from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging
import time
import os
from collections import deque
from datetime import datetime, timedelta

class FileSystemMonitor(FileSystemEventHandler):
    def __init__(self, detector, mitigator):
        self.detector = detector
        self.mitigator = mitigator
        self.recent_events = deque(maxlen=1000)
        self.threat_threshold = 70  # Threshold for taking action
        
        logging.basicConfig(
            filename='monitor.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
    def on_modified(self, event):
        if event.is_directory:
            return
            
        self._process_event(event, 'modified')
        
    def on_created(self, event):
        if event.is_directory:
            return
            
        self._process_event(event, 'created')
        
    def on_deleted(self, event):
        if event.is_directory:
            return
            
        self._process_event(event, 'deleted')

    def _process_event(self, event, event_type):
        current_time = datetime.now()
        self.recent_events.append({
            'time': current_time,
            'type': event_type,
            'path': event.src_path
        })
        
        # Analyze recent events
        self._analyze_events()
        
        # Get current threat score
        threat_score = self.detector.get_threat_score()
        
        # Log event
        logging.info(f"File {event_type}: {event.src_path} - Threat Score: {threat_score}")
        
        # Take action if threat score is high
        if threat_score >= self.threat_threshold:
            self._take_protective_action()

    def _analyze_events(self):
        """Analyze recent events for patterns"""
        current_time = datetime.now()
        minute_ago = current_time - timedelta(minutes=1)
        
        # Count recent events
        recent_count = sum(1 for event in self.recent_events 
                          if event['time'] > minute_ago)
        
        # Check for suspicious patterns
        if recent_count > 100:  # More than 100 events per minute
            logging.warning(f"High file activity detected: {recent_count} events/minute")
            
        # Check for mass deletions
        deletion_count = sum(1 for event in self.recent_events 
                           if event['time'] > minute_ago and event['type'] == 'deleted')
        if deletion_count > 50:  # More than 50 deletions per minute
            logging.warning(f"Mass file deletion detected: {deletion_count} deletions/minute")

    def _take_protective_action(self):
        """Take protective actions when threat is detected"""
        logging.warning("Taking protective actions...")
        
        # Create emergency backup
        self.mitigator.create_backup()
        
        # Get suspicious processes from detector
        suspicious_processes = list(self.detector.suspicious_processes)
        
        # Terminate suspicious processes
        self.mitigator.terminate_suspicious_processes(suspicious_processes)
        
        logging.info("Protective actions completed")

def start_monitoring(paths, detector, mitigator):
    """Start monitoring the specified paths"""
    event_handler = FileSystemMonitor(detector, mitigator)
    observer = Observer()
    
    for path in paths:
        if os.path.exists(path):
            observer.schedule(event_handler, path, recursive=True)
            logging.info(f"Started monitoring: {path}")
    
    observer.start()
    return observer, event_handler