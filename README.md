# Advanced Log Analysis Tool with Machine Learning and Real-Time Monitoring

This Python-based tool uses **machine learning**, **real-time log monitoring**, and **automated alerting** to detect anomalies and potential security threats in log data. It is designed for scalability, making it suitable for organizations handling large volumes of log data.

### **Features**
- **Log Parsing**: Efficiently parses Apache-style log files to extract useful data such as IP address, timestamp, status code, and request size.
- **Anomaly Detection**: Utilizes **Isolation Forest** for machine learning-based anomaly detection to identify unusual behavior like traffic spikes, failed logins, and other potential security threats.
- **Real-Time Monitoring**: Monitors log files in real-time using the **watchdog** library, triggering automatic analysis and alerts when new log entries are added.
- **Alerting**: Sends **email notifications** when an anomaly is detected, detailing suspicious activities for immediate action.
- **Scalability**: Handles large log files and multiple log sources efficiently using **pandas**, with the potential for integration with distributed frameworks like **Dask** or **PySpark**.
- **Visualization**: Visualizes detected anomalies over time using **Seaborn** and **Matplotlib** to help understand log trends.

### **Technologies Used**
- **Python** libraries: `pandas`, `seaborn`, `matplotlib`, `scikit-learn`, `watchdog`, `smtplib`
- **Machine Learning**: Isolation Forest for anomaly detection, StandardScaler for feature scaling
- **Email Notifications**: `smtplib` for alerting via email
- **Real-Time Monitoring**: `watchdog` for log file monitoring

### **How to Use**
1. Clone the repository:
   ```bash
   git clone https://github.com/andreaskon51/Log-Analysis-Python.git
   cd Log-Analysis-Python
   ```
2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the tool:
   ```bash
   python Log Analysis.py
   ```
4. Enter the path to your log file when prompted.
5. The tool will begin processing logs and detect anomalies in real-time. If an anomaly is detected, you will receive an email alert.

### **Configuration**
- To set up email alerts, configure the following parameters in the script:
   - `sender_email`: Your email address (e.g., Gmail).
   - `receiver_email`: The email address that will receive alerts.
   - SMTP server configuration (for Gmail, use `smtp.gmail.com` with port `587`).

### **Use Cases**
- **Security Monitoring**: Detect brute force attacks, DDoS attempts, or unauthorized access attempts.
- **Compliance & Auditing**: Monitor log data for abnormal behavior and ensure compliance with regulations (e.g., HIPAA, GDPR).
- **System Performance**: Identify application errors or performance bottlenecks based on log data.

### **Example Output**
The tool will print detected anomalies and send email alerts if it identifies any suspicious activity, such as:
- Unusual spikes in failed login attempts
- High request rates from specific IP addresses
- Unusual HTTP status codes (e.g., 500 errors)

### **Contributing**
Feel free to contribute! Fork the repo, create a new branch, and submit a pull request. Ensure your contributions adhere to the existing code style and include tests where necessary.
