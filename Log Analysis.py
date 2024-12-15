import re
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
from collections import Counter
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading

# Utility function to parse Apache logs
def parse_log_line(line):
    """
    Parse an Apache log line and extract relevant details (IP, timestamp, status, etc.).
    Assumes Apache log format is used: '127.0.0.1 - - [12/Oct/2023:10:00:00 -0700] "GET /index.html HTTP/1.1" 200 2326'
    """
    log_pattern = r'(?P<ip>[\d\.]+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>\w+) (?P<endpoint>\S+) HTTP/\d+\.\d+" (?P<status_code>\d+) (?P<size>\d+)'
    match = re.match(log_pattern, line)
    if match:
        return match.groupdict()
    return None

# Machine learning model for anomaly detection
class LogAnalyzer:
    def __init__(self):
        self.model = None
        self.scaler = None

    def fit_anomaly_detector(self, df):
        """
        Fit an Isolation Forest model to the log data to detect anomalies.
        """
        df_clean = df[['hour', 'status_code', 'size']].copy()
        df_clean['status_code'] = df_clean['status_code'].astype(int)
        df_clean = df_clean.fillna(0)
        features = df_clean[['hour', 'status_code', 'size']].values

        # Scale the data
        self.scaler = StandardScaler()
        features_scaled = self.scaler.fit_transform(features)

        # Fit Isolation Forest model
        self.model = IsolationForest(contamination=0.05, random_state=42)
        self.model.fit(features_scaled)

    def predict_anomalies(self, df):
        """
        Predict anomalies using the trained model.
        """
        if self.model is None:
            raise ValueError("Model has not been trained. Call fit_anomaly_detector() first.")

        df_clean = df[['hour', 'status_code', 'size']].copy()
        df_clean['status_code'] = df_clean['status_code'].astype(int)
        df_clean = df_clean.fillna(0)
        features = df_clean[['hour', 'status_code', 'size']].values

        # Scale the data
        features_scaled = self.scaler.transform(features)

        # Predict anomalies
        predictions = self.model.predict(features_scaled)
        df['anomaly'] = predictions
        return df[df['anomaly'] == -1]

# Real-time log monitoring class
class LogMonitor:
    def __init__(self, log_file_path, log_analyzer):
        self.log_file_path = log_file_path
        self.log_analyzer = log_analyzer
        self.df = pd.DataFrame(columns=['ip', 'timestamp', 'method', 'endpoint', 'status_code', 'size'])

    def on_created(self, event):
        # This will be triggered when a new line is added to the log file
        if event.src_path == self.log_file_path:
            with open(self.log_file_path, 'r') as f:
                lines = f.readlines()
                new_line = lines[-1]
                log_entry = parse_log_line(new_line)
                if log_entry:
                    self.df = self.df.append(log_entry, ignore_index=True)

                # Analyze the logs with the trained model
                detected_anomalies = self.log_analyzer.predict_anomalies(self.df)
                if not detected_anomalies.empty:
                    self.send_alert(f"Anomaly Detected: {detected_anomalies}")
                    print(f"Anomaly detected: {detected_anomalies}")

    def send_alert(self, message):
        """
        Send an email alert if an anomaly is detected.
        """
        try:
            sender_email = "youremail@example.com"
            receiver_email = "receiver@example.com"
            password = "yourpassword"

            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = receiver_email
            msg['Subject'] = 'Log Monitoring Alert'

            msg.attach(MIMEText(message, 'plain'))

            # Send email
            server = smtplib.SMTP('smtp.example.com', 587)
            server.starttls()
            server.login(sender_email, password)
            text = msg.as_string()
            server.sendmail(sender_email, receiver_email, text)
            server.quit()

            print(f"Alert sent: {message}")
        except Exception as e:
            print(f"Failed to send alert: {e}")

    def start_monitoring(self):
        event_handler = FileSystemEventHandler()
        event_handler.on_created = self.on_created

        observer = Observer()
        observer.schedule(event_handler, path=self.log_file_path, recursive=False)
        observer.start()
        print("Started real-time monitoring...")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()

# Main function to run the analysis
def main():
    file_path = input("Enter the log file path: ")
    df = pd.read_csv(file_path, names=['ip', 'timestamp', 'method', 'endpoint', 'status_code', 'size'])

    # Convert timestamp to datetime
    df['timestamp'] = pd.to_datetime(df['timestamp'], format='%d/%b/%Y:%H:%M:%S %z')

    # Train the anomaly detector
    analyzer = LogAnalyzer()
    analyzer.fit_anomaly_detector(df)

    # Perform anomaly detection
    anomalies = analyzer.predict_anomalies(df)
    if not anomalies.empty:
        print("\nAnomalies detected:")
        print(anomalies)

    # Visualize anomalies
    plt.figure(figsize=(10, 6))
    sns.countplot(x='hour', data=anomalies)
    plt.title('Anomalous Events by Hour')
    plt.show()

    # Start real-time log monitoring
    monitor = LogMonitor(file_path, analyzer)
    monitor.start_monitoring()

if __name__ == "__main__":
    main()
