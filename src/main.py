import os
from detection.detector import RansomwareDetector
from mitigation.mitigator import RansomwareMitigator
from monitoring.monitor import start_monitoring
import logging
import time

def main():
    # Configure paths
    monitored_paths = [
        os.path.join(os.getcwd(), "data", "critical"),
        # Add more paths as needed
    ]
    
    backup_dir = os.path.join(os.getcwd(), "data", "backups")
    
    # Ensure backup directory exists
    os.makedirs(backup_dir, exist_ok=True)
    
    # Initialize components
    detector = RansomwareDetector(monitored_paths)
    mitigator = RansomwareMitigator(monitored_paths, backup_dir)
    
    # Start monitoring
    observer, monitor = start_monitoring(monitored_paths, detector, mitigator)
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping monitoring...")
        observer.stop()
        detector.stop_monitoring()
        mitigator.stop_service()
        observer.join()

if __name__ == "__main__":
    main()