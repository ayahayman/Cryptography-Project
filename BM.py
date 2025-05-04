import argparse
import re
import time
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import defaultdict
import math
import os
import stat
import platform
import subprocess

# === Settings ===
SUSPICIOUS_EXTENSIONS = ['.locked', '.encrypted', '.payforunlock', '.enc']
COMPRESSED_EXTENSIONS = ['.zip', '.rar', '.7z', '.tar', '.gz']
SUSPICIOUS_FOLDERS = ['temp', 'appdata', 'downloads']

if platform.system() == "Windows":
    WHITELISTED_PROCESSES = [
        'explorer.exe', 'System Idle Process', 'System', 'svchost.exe', 'csrss.exe',
        'wininit.exe', 'smss.exe', 'lsass.exe', 'services.exe', 'taskhostw.exe',
        'SearchIndexer.exe', 'OneDrive.exe', 'chrome.exe', 
    ]
    CRITICAL_PATHS = [
        "C:\\Windows\\System32",
        "C:\\Windows\\Registry",
        "C:\\Program Files",
        os.path.expandvars("%APPDATA%")
    ]
    DEFAULT_PATH = "C:\\TestFolder"
else:
    WHITELISTED_PROCESSES = ['launchd', 'WindowServer', 'kernel_task', 'loginwindow']
    CRITICAL_PATHS = [
        "/System/Library",
        "/Library",
        "/Applications",
        os.path.expanduser("~/Library")
    ]
    DEFAULT_PATH = os.path.expanduser("~/Desktop/security_project/testFolder")

CPU_USAGE_THRESHOLD = 50
SCORE_THRESHOLD = 100  # More strict
MASS_FILE_CREATE_THRESHOLD = 30
BIG_SCORE_FOR_MASS_WRITE = 5
MASS_FILE_DELETION_THRESHOLD = 30
BIG_SCORE_FOR_MASS_DELETION = 5
OUTBOUND_NETWORK_SPIKE = 100_0000 

test_mode = False

# === Globals ===
process_scores = defaultdict(int)
process_safe_creation = defaultdict(lambda: True)
process_file_create_counter = defaultdict(int)
process_deletion_counter = defaultdict(int)
process_net_usage = defaultdict(lambda: {'sent': 0, 'recv': 0})
last_mass_check_time = time.time()
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
        entropy = -sum(p * math.log2(p) for p in (count / len(data) for count in byte_counts if count))
        return entropy
    except Exception:
        return 0.0

def log_alert(message):
    with open("alerts.log", "a") as log:
        log.write(f"{time.ctime()}: {message}\n")

def check_score_threshold(pid, name):
    if process_safe_creation[pid]:  
        return
    if process_scores[pid] >= SCORE_THRESHOLD:
        msg = f"[!!!] ALERT: {name} (PID {pid}) flagged! Score = {process_scores[pid]}"
        print(msg)
        log_alert(msg)
        if not test_mode:
            try:
                psutil.Process(pid).kill()
            except Exception:
                pass
            
def is_gibberish(name):
    base = os.path.basename(name).split('.')[0]
    return bool(re.fullmatch(r'[a-zA-Z0-9]{8,}', base))


def check_critical_path_access(path, pid, name):
    if any(path.startswith(p) for p in CRITICAL_PATHS):
        print(f"[!!!] Unauthorized access to critical path: {path} by {name} (PID {pid})")
        process_scores[pid] += 5
        check_score_threshold(pid, name)

class FileEventHandler(FileSystemEventHandler):
    def on_created(self, event):
        entropy = calculate_entropy(event.src_path)
        print(f"[*] Entropy of {event.src_path}: {entropy:.2f}")
        suspicious_ext = any(event.src_path.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)
        compressed_ext = any(event.src_path.lower().endswith(ext) for ext in COMPRESSED_EXTENSIONS)
        is_hidden = os.path.basename(event.src_path).startswith('.') if platform.system() != "Windows" else False

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                if name in WHITELISTED_PROCESSES:
                    continue
                process_file_create_counter[pid] += 1
                check_critical_path_access(event.src_path, pid, name)

                if is_hidden:
                    print(f"[!!!] Hidden file created by {name} (PID {pid})")
                    process_scores[pid] += 4
                    process_safe_creation[pid] = False  
                if suspicious_ext:
                    print(f"[!!!] Suspicious file extension detected by {name} (PID {pid})")
                    process_scores[pid] += 4
                    process_safe_creation[pid] = False  
                if entropy > 7.5:
                    if compressed_ext:
                        print(f"[!] High entropy compressed file by {name} (PID {pid})")
                        process_scores[pid] += 1
                    else:
                        print(f"[!!!] High entropy encrypted file by {name} (PID {pid})")
                        process_scores[pid] += 3
                        process_safe_creation[pid] = False  

                check_score_threshold(pid, name)
                break
            except Exception:
                continue

        self.check_mass_file_creation()

    def on_deleted(self, event):
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'] in WHITELISTED_PROCESSES:
                    continue
                pid = proc.info['pid']
                name = proc.info['name']
                process_deletion_counter[pid] += 1
                check_critical_path_access(event.src_path, pid, name)
                print(f"[!] File deleted by {name} (PID {pid})")
                check_score_threshold(pid, name)
                break
            except Exception:
                continue
        self.check_mass_deletions()
        
    def on_moved(self, event):
        if event.is_directory:
            return

        print(f"on move")
        if any(event.dest_path.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS) or is_gibberish(event.dest_path):
            log_alert(f"[!!!] Suspicious file rename to {event.dest_path}")

            print(f"[!!!] Suspicious file rename to {event.dest_path}")
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    pid = proc.info['pid']
                    name = proc.info['name']

                    if name in WHITELISTED_PROCESSES:
                        continue

                  
                    process_scores[pid] += 4
                    process_safe_creation[pid] = False  # Mark as unsafe
                    check_score_threshold(pid, name)
                    break  
                except Exception:
                    continue


    def check_mass_file_creation(self):
        global last_mass_check_time
        for pid, count in process_file_create_counter.items():
            if count > MASS_FILE_CREATE_THRESHOLD:
                print(f"[!!!] Mass file creation: PID {pid} created {count} files!")
                process_scores[pid] += BIG_SCORE_FOR_MASS_WRITE
                check_score_threshold(pid, psutil.Process(pid).name())
        if time.time() - last_mass_check_time > 60:
            process_file_create_counter.clear()
            last_mass_check_time = time.time()

    def check_mass_deletions(self):
        global deletion_check_time
        for pid, count in process_deletion_counter.items():
            if count > MASS_FILE_DELETION_THRESHOLD:
                print(f"[!!!] Mass deletion: PID {pid} deleted {count} files!")
                process_scores[pid] += BIG_SCORE_FOR_MASS_DELETION
                check_score_threshold(pid, psutil.Process(pid).name())
        if time.time() - deletion_check_time > 60:
            process_deletion_counter.clear()
            deletion_check_time = time.time()

def check_high_cpu_usage():
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] in WHITELISTED_PROCESSES:
                continue
            check_suspicious_exec_path(proc)
            cpu = proc.cpu_percent(interval=0.1)
            if cpu > CPU_USAGE_THRESHOLD + 20:
                process_scores[proc.pid] += 4
            elif cpu > CPU_USAGE_THRESHOLD + 10:
                process_scores[proc.pid] += 3
            elif cpu > CPU_USAGE_THRESHOLD:
                process_scores[proc.pid] += 2
        except Exception:
            continue

def monitor_network_usage():
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] in WHITELISTED_PROCESSES:
                continue
            check_suspicious_exec_path(proc)
            net = proc.net_io_counters()
            if net and net.bytes_sent > OUTBOUND_NETWORK_SPIKE:
                print(f"[!!!] High outbound traffic from {proc.info['name']} (PID {proc.pid}) - Sent: {net.bytes_sent} bytes")
                process_scores[proc.pid] += 8
                check_score_threshold(proc.pid, proc.info['name'])
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            continue
        
def check_suspicious_exec_path(proc):
    try:
        path = proc.exe().lower()
        if any(folder in path for folder in SUSPICIOUS_FOLDERS):
            msg = f"[!!!] Process running from suspicious path: {path}"
            log_alert(msg)
            process_scores[proc.pid] += 3
            check_score_threshold(proc.pid, proc.name())
    except Exception:
        pass
    
def detect_new_services(existing_services):
    try:
        output = subprocess.check_output(
            "wmic service get Name,PathName,StartMode", shell=True
        ).decode()
        lines = output.strip().split("\n")[1:]
        current_services = set()
        new_suspicious = []

        for line in lines:
            parts = line.strip().split(None, 2)
            if len(parts) < 2:
                continue
            name, path = parts[0], parts[1]
            current_services.add(name)

            if name not in existing_services:
                if any(k in path.lower() for k in ['ransom', 'encrypt', 'crypto']):
                    log_alert(f"[!!!] Suspicious service created: {name} -> {path}")
                    new_suspicious.append(path)

        # Try to find matching process and score it
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                if proc.info['exe'] and any(sus.lower() in proc.info['exe'].lower() for sus in new_suspicious):
                    process_scores[proc.pid] += 5
                    log_alert(f"[!] Linked suspicious service to process: {proc.info['name']} (PID {proc.pid})")
                    check_score_threshold(proc.pid, proc.info['name'])
            except Exception:
                continue

        return current_services
    except Exception as e:
        log_alert(f"[ERROR] Service scan failed: {e}")
        return existing_services

def list_services():
    output = subprocess.check_output("wmic service get Name,DisplayName", shell=True).decode()
    return set(line.strip() for line in output.split("\n")[1:] if line.strip())

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
    service_snapshot = list_services() 

    os.makedirs(DEFAULT_PATH, exist_ok=True)
    event_handler = FileEventHandler()
    observer = Observer()
    observer.schedule(event_handler, path=DEFAULT_PATH, recursive=True)
    observer.start()

    print("[*] Behavioral Monitor Started. Test mode =", test_mode)
    try:
        while True:
            if time.time() - last_service_check > 30:
                service_snapshot = detect_new_services(service_snapshot)
                last_service_check = time.time()

           
            check_high_cpu_usage()
            monitor_network_usage()
            show_top_suspects()
            time.sleep(5)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

