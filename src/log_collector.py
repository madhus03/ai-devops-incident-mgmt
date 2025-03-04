import subprocess
import os
import signal
import sys
from datetime import datetime

class RealTimeLogCollector:
    """
    A real-time log collection utility that monitors system logs dynamically.
    """

    def __init__(self, log_file_path="/var/log/syslog", output_file="collected_logs.txt"):
        """
        Initializes the log collector with the specified log file path and output file.
        """
        self.log_file_path = log_file_path
        self.output_file = output_file
        self.process = None  # Placeholder for subprocess

    def start_collection(self):
        """
        Starts collecting logs in real-time using the `tail -f` command.
        Logs are written to the specified output file.
        """
        try:
            # Ensure the log file exists before proceeding
            if not os.path.exists(self.log_file_path):
                raise FileNotFoundError(f"Log file {self.log_file_path} not found.")

            print(f"Monitoring logs from: {self.log_file_path}")
            print(f"Storing collected logs in: {self.output_file}")
            print("Press Ctrl+C to stop collecting logs.\n")

            with open(self.output_file, "a") as outfile:
                self.process = subprocess.Popen(
                    ["tail", "-f", self.log_file_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                # Read logs in real-time
                for line in iter(self.process.stdout.readline, ''):
                    timestamped_log = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {line.strip()}\n"
                    outfile.write(timestamped_log)
                    outfile.flush()
                    print(timestamped_log, end="")

        except KeyboardInterrupt:
            print("\n Log collection stopped by user.")
            self.stop_collection()
        except FileNotFoundError as fnf_error:
            print(f"Error: {fnf_error}")
        except Exception as e:
            print(f"Unexpected Error: {e}")

    def stop_collection(self):
        """
        Gracefully stops the log collection process.
        """
        if self.process:
            self.process.terminate()
            print("Log collection process terminated.")

# Run the log collector
if __name__ == "__main__":
    log_collector = RealTimeLogCollector()
    log_collector.start_collection()

