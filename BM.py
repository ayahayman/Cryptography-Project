import argparse
import time
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import defaultdict
import math
import os
import stat
import platform

# === Settings ===
SUSPICIOUS_EXTENSIONS = ['.locked', '.encrypted', '.payforunlock', '.enc']
COMPRESSED_EXTENSIONS = ['.zip', '.rar', '.7z', '.tar', '.gz']

if platform.system() == "Windows":
    WHITELISTED_PROCESSES = [
        'explorer.exe', 'System Idle Process', 'System', 'svchost.exe', 'csrss.exe',
        'wininit.exe', 'smss.exe', 'lsass.exe', 'services.exe', 'taskhostw.exe',
        'SearchIndexer.exe', 'OneDrive.exe', 'chrome.exe', 'python.exe', 'pythonw.exe'
    ]
    CRITICAL_PATHS = [
        "C:\\Windows\\System32",
        "C:\\Windows\\Registry",
        "C:\\Program Files",
        os.path.expandvars("%APPDATA%")
    ]
    DEFAULT_PATH = "C:\\TestFolder"
else:
    WHITELISTED_PROCESSES = ['launchd', 'WindowServer', 'kernel_task', 'loginwindow', 'python3', 'python3.12']
    CRITICAL_PATHS = [
        "/System/Library",
        "/Library",
        "/Applications",
        os.path.expanduser("~/Library")
    ]
    DEFAULT_PATH = os.path.expanduser("~/Desktop/security project/testFolder")

CPU_USAGE_THRESHOLD = 50
SCORE_THRESHOLD = 80
MASS_FILE_CREATE_THRESHOLD = 30
BIG_SCORE_FOR_MASS_WRITE = 10
MASS_FILE_MODIFICATION_THRESHOLD = 30
BIG_SCORE_FOR_MASS_MODIFICATION = 10
MASS_FILE_DELETION_THRESHOLD = 30
BIG_SCORE_FOR_MASS_DELETION = 10

test_mode = False

# === Globals ===
process_scores = defaultdict(int)
process_file_create_counter = defaultdict(int)
process_modification_counter = defaultdict(int)
process_deletion_counter = defaultdict(int)
last_mass_check_time = time.time()
modification_check_time = time.time()
deletion_check_time = time.time()

def calculate_entropy(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        if not data:
            return 0.0
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        entropy = 0
        for count in byte_counts:
            if count == 0:
                continue
            p = count / len(data)
            entropy -= p * math.log2(p)
        return entropy
    except Exception:
        return 0.0

def log_alert(message):
    with open("alerts.log", "a") as log:
        log.write(f"{time.ctime()}: {message}\n")

class FileEventHandler(FileSystemEventHandler):
    def check_score_threshold(self, pid, name):
        if process_scores[pid] >= SCORE_THRESHOLD:
            msg = f"[!!!] ALERT: {name} (PID {pid}) flagged! Score = {process_scores[pid]}"
            print(msg)
            log_alert(msg)
            if not test_mode:
                try:
                    psutil.Process(pid).kill()
                except Exception:
                    pass

    def check_critical_path_access(self, path, pid, name):
        if any(path.startswith(p) for p in CRITICAL_PATHS):
            print(f"[!!!] Unauthorized access to critical path: {path} by {name} (PID {pid})")
            process_scores[pid] += 5
            self.check_score_threshold(pid, name)

    def on_created(self, event):
        # Debugging: Log the event
        #print(f"[DEBUG] on_created triggered for: {event.src_path}"

        # Calculate entropy and log it
        entropy = calculate_entropy(event.src_path)
        print(f"[*] Entropy of {event.src_path}: {entropy:.2f}")

        # Ensure case-insensitive matching for suspicious extensions
        suspicious_ext = any(event.src_path.lower().endswith(ext.lower()) for ext in SUSPICIOUS_EXTENSIONS)
        compressed_ext = any(event.src_path.lower().endswith(ext.lower()) for ext in COMPRESSED_EXTENSIONS)

        # Debugging: Log whether the file has a suspicious extension
        if suspicious_ext:
            print(f"[!!!] Suspicious file extension detected: {event.src_path}")
      
       
        is_hidden = False
        try:
            file_attributes = os.stat(event.src_path)
            is_hidden = bool(file_attributes.st_file_attributes & stat.FILE_ATTRIBUTE_HIDDEN) if platform.system() == "Windows" else os.path.basename(event.src_path).startswith('.')
            
            if is_hidden:
                print(f"[!!!] Hidden file detected: {event.src_path}")
    
        except Exception as e:
            print(f"[DEBUG] Error checking hidden attribute: {e}")

        # Match file to process
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                if proc.info['name'] in WHITELISTED_PROCESSES:
                    
                    continue
                process_file_create_counter[pid] += 1
                self.check_critical_path_access(event.src_path, pid, name)
                if is_hidden:
                    print(f"[!!!] Hidden file created by {name} (PID {pid})")
                    process_scores[pid] += 6
                if suspicious_ext:
                    print(f"[!!!] Suspicious file extension detected by {name} (PID {pid})")
                    process_scores[pid] += 5
                if entropy > 7.5:
                    if compressed_ext:
                        print(f"[!] High entropy compressed file by {name} (PID {pid})")
                        process_scores[pid] += 1
                    else:
                        print(f"[!!!] High entropy encrypted file by {name} (PID {pid})")
                        process_scores[pid] += 3
                self.check_score_threshold(pid, name)
                break
            except Exception as e:
                print(f"[DEBUG] Error processing file creation: {e}")

        # Check for mass file creation
        self.check_mass_file_creation_per_process()

    # def on_modified(self, event):
    #     for proc in psutil.process_iter(['pid', 'name']):
    #         try:
    #             if proc.info['name'] in WHITELISTED_PROCESSES:
    #                 continue
    #             pid = proc.info['pid']
    #             name = proc.info['name']
    #             process_modification_counter[pid] += 1
    #             self.check_critical_path_access(event.src_path, pid, name)
    #             print(f"[+] Modified by {name} (PID {pid})")
    #             self.check_score_threshold(pid, name)
    #             break
    #         except Exception:
    #             continue
    #     self.check_mass_modifications()

    def on_deleted(self, event):
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'] in WHITELISTED_PROCESSES:
                    continue
                pid = proc.info['pid']
                name = proc.info['name']
                process_deletion_counter[pid] += 1
                self.check_critical_path_access(event.src_path, pid, name)
                print(f"[!] File deleted by {name} (PID {pid})")
                self.check_score_threshold(pid, name)
                break
            except Exception:
                continue
        self.check_mass_deletions()

    def check_mass_file_creation_per_process(self):
        global last_mass_check_time
        
        for pid, count in process_file_create_counter.items():
            if count > MASS_FILE_CREATE_THRESHOLD:
                print(f"[!!!] Mass file creation: PID {pid} created {count} files!")
                process_scores[pid] += BIG_SCORE_FOR_MASS_WRITE
                if time.time() - last_mass_check_time > 60:
                    process_file_create_counter.clear()
                    last_mass_check_time = time.time()

    def check_mass_modifications(self):
        global modification_check_time
        
        for pid, count in process_modification_counter.items():
            if count > MASS_FILE_MODIFICATION_THRESHOLD:
                print(f"[!!!] Mass modification: PID {pid} modified {count} files!")
                process_scores[pid] += BIG_SCORE_FOR_MASS_MODIFICATION
                if time.time() - modification_check_time > 60:
                    process_modification_counter.clear()
                    modification_check_time = time.time()

    def check_mass_deletions(self):
        global deletion_check_time
        
        for pid, count in process_deletion_counter.items():
            if count > MASS_FILE_DELETION_THRESHOLD:
                print(f"[!!!] Mass deletion: PID {pid} deleted {count} files!")
                process_scores[pid] += BIG_SCORE_FOR_MASS_DELETION
                if time.time() - deletion_check_time > 60:
                    process_deletion_counter.clear()
                    deletion_check_time = time.time()

def check_high_cpu_usage():
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            proc.cpu_percent(interval=None)
        except Exception:
            continue
    time.sleep(1)
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
        try:
            if proc.info['name'] in WHITELISTED_PROCESSES:
                continue
            cpu = proc.cpu_percent(interval=None)
            if cpu > CPU_USAGE_THRESHOLD + 20:
                process_scores[proc.info['pid']] += 4
            elif cpu > CPU_USAGE_THRESHOLD + 10:
                process_scores[proc.info['pid']] += 3
            elif cpu > CPU_USAGE_THRESHOLD:
                process_scores[proc.info['pid']] += 2
        except Exception:
            continue

def show_top_suspects():
    top = sorted(process_scores.items(), key=lambda x: x[1], reverse=True)[:5]
    print("\n[Live Dashboard] Top Suspicious Processes:")
    for pid, score in top:
        try:
            name = psutil.Process(pid).name()
            print(f"  PID: {pid} | Name: {name} | Score: {score}")
        except Exception:
            continue
    print("-" * 40)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-mode", action="store_true", help="Run in simulation mode without killing processes.")
    args = parser.parse_args()
    test_mode = args.test_mode

    os.makedirs(DEFAULT_PATH, exist_ok=True)
    event_handler = FileEventHandler()
    observer = Observer()
    observer.schedule(event_handler, path=DEFAULT_PATH, recursive=True)
    #observer.schedule(event_handler, path="/Library", recursive=True)

    observer.start()

    print("[*] Behavioral Monitor Started. Test mode =", test_mode)
    try:
        while True:
            check_high_cpu_usage()
            show_top_suspects()
            time.sleep(5)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
