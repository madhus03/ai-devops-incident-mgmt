import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
import requests

LOG_FILE_PATH = "collected_logs.txt"
ANOMALY_LOG_FILE = "anomaly_log.txt"  # File to store anomalies
ANOMALY_KEYWORDS = ["ERROR", "WARNING", "FAILED", "CRITICAL", "EXCEPTION"]

# Slack webhook URL (replace with your actual webhook URL)
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/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"

def send_slack_alert(message):
    """
    Sends an alert message to Slack.
    """
    payload = {"text": message}
    try:
        response = requests.post(SLACK_WEBHOOK_URL, json=payload)
        if response.status_code == 200:
            print("[INFO] Slack notification sent successfully.")
        else:
            print(f"[WARNING] Failed to send Slack notification. Status Code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Exception while sending Slack notification: {str(e)}")

class LogFileHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_position = 0
        self.first_run = True  # Ensure initial read on startup
    
    def on_modified(self, event):
        if event.src_path.endswith(LOG_FILE_PATH):
            print("\n[INFO] Log file modified. Checking for new entries...\n")
            self.process_log_file()

    def process_log_file(self):
        try:
            with open(LOG_FILE_PATH, "r") as log_file:
                if self.first_run:
                    print("[DEBUG] First run - reading entire log file")
                    log_file.seek(0)  # Read from the beginning on first run
                    self.first_run = False
                else:
                    log_file.seek(self.last_position)  # Read only new logs
                new_logs = log_file.readlines()
                self.last_position = log_file.tell()  # Update last position

            if new_logs:
                print(f"[DEBUG] New logs detected: {len(new_logs)} entries")
                for log in new_logs:
                    log = log.strip()
                    print(f"[LOG] {log}")  # Debug output to check logs
                    if any(keyword in log for keyword in ANOMALY_KEYWORDS):
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        anomaly_entry = f"{timestamp} - {log}\n"

                        # Save anomaly to file
                        with open(ANOMALY_LOG_FILE, "a") as file:
                            file.write(anomaly_entry)

                        print(f"\n🚨 Anomaly Detected: {log}")
                        print("[INFO] Anomaly saved to anomaly_log.txt")

                        # Send alert to Slack
                        send_slack_alert(f"🚨 Anomaly Detected: {log}")
            else:
                print("✅ No new logs detected.")

        except Exception as e:
            print(f"\n❌ Error processing log file: {str(e)}")

def start_monitoring():
    event_handler = LogFileHandler()
    observer = Observer()
    observer.schedule(event_handler, path=".", recursive=False)
    observer.start()
    print(f"\n🔍 Monitoring {LOG_FILE_PATH} for real-time logs...\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    start_monitoring()
