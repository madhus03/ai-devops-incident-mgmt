import re
from datetime import datetime

# Define file paths
LOG_FILE_PATH = "collected_logs.txt"
ANOMALY_FILE_PATH = "anomalies_detected.txt"

# List of keywords to detect anomalies
ANOMALY_KEYWORDS = ["ERROR", "WARNING", "FAILED", "CRITICAL", "EXCEPTION"]

def detect_anomalies():
    """
    Reads the log file, detects anomalies based on defined keywords, 
    and saves them to a separate file.
    """
    try:
        with open(LOG_FILE_PATH, "r") as log_file:
            logs = log_file.readlines()

        print("\n[INFO] Scanning logs for anomalies...\n")

        anomaly_logs = []
        for line in logs:
            if any(keyword in line for keyword in ANOMALY_KEYWORDS):
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                formatted_log = f"[{timestamp}] {line.strip()}"
                anomaly_logs.append(formatted_log)

        if anomaly_logs:
            print("\n🚨 Anomalies Detected in Logs 🚨")
            for log in anomaly_logs:
                print(log)
            
            # Save anomalies to a separate file
            with open(ANOMALY_FILE_PATH, "a") as anomaly_file:
                anomaly_file.write("\n".join(anomaly_logs) + "\n")

            print(f"\n[INFO] Anomalies saved to '{ANOMALY_FILE_PATH}'.")

        else:
            print("\n✅ No anomalies detected in logs.")

    except FileNotFoundError:
        print(f"\n❌ Error: Log file '{LOG_FILE_PATH}' not found.")
    except Exception as e:
        print(f"\n❌ Unexpected error occurred: {str(e)}")

# Run the anomaly detection function
if __name__ == "__main__":
    detect_anomalies()
