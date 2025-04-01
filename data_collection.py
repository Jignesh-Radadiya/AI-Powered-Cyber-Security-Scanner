### Data Collect from System ###


import tkinter as tk
from tkinter import filedialog, messagebox
import psutil
import csv
import os
import time

class DataCollectionApp:
    """Data Collection Interface for System Logs & AI Threat Analysis."""
    
    def __init__(self, parent):
        """Initialize the data collection interface inside the main application."""
        self.frame = tk.Frame(parent, bg="#1E1E1E")
        self.frame.pack(fill="both", expand=True)

        self.label = tk.Label(self.frame, text="📥 Data Collection & AI Threat Logs", font=("Arial", 14, "bold"), fg="white", bg="#1E1E1E")
        self.label.pack(pady=10)

        self.text_area = tk.Text(self.frame, height=20, width=100, bg="#2E2E2E", fg="lime", font=("Arial", 10), insertbackground="white")
        self.text_area.pack(pady=10)
        self.text_area.tag_configure("green", foreground="lime")

        # Buttons
        btn_collect_logs = tk.Button(self.frame, text="📥 Collect System Logs", command=self.collect_system_logs, bg="#2980B9", fg="white", font=("Arial", 10, "bold"))
        btn_collect_logs.pack(pady=5)

        btn_collect_ai = tk.Button(self.frame, text="🤖 Collect AI Threat Data", command=self.collect_ai_threat_data, bg="#27AE60", fg="white", font=("Arial", 10, "bold"))
        btn_collect_ai.pack(pady=5)

        btn_export_logs = tk.Button(self.frame, text="📤 Export System Logs", command=self.export_system_logs_csv, bg="#E67E22", fg="white", font=("Arial", 10, "bold"))
        btn_export_logs.pack(pady=5)

        btn_export_threats = tk.Button(self.frame, text="🚨 Export AI Threat Data", command=self.export_threat_data_csv, bg="#C0392B", fg="white", font=("Arial", 10, "bold"))
        btn_export_threats.pack(pady=5)

    def collect_system_logs(self):
        """Collect system logs from CPU, RAM, and /var/log/auth.log."""
        logs = [
            f"🔹 CPU Usage: {psutil.cpu_percent()}%",
            f"🔹 Memory Usage: {psutil.virtual_memory().percent}%",
            f"🔹 Active Processes: {len(psutil.pids())}"
        ]

        # Read auth.log for login failures
        auth_log_path = "/var/log/auth.log"
        if os.path.exists(auth_log_path):
            with open(auth_log_path, "r") as log_file:
                auth_logs = log_file.readlines()[-10:]  # Read last 10 lines
            logs.append("\n🔹 **Last 10 Authentication Logs:**")
            logs.extend(auth_logs)
        else:
            logs.append("❌ Authentication log file not found.")

        log_data = "\n".join(logs)
        self.text_area.insert(tk.END, log_data + "\n\n","green")
        
        self.text_area.see(tk.END)

    def collect_ai_threat_data(self):
        """Extract potential AI threat indicators from various sources."""
        ai_threats = []
        suspicious_ips = set()
        failed_login_attempts = 0
        firewall_alerts = 0
        network_traffic = psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
        network_traffic_mb = round(network_traffic / (1024 * 1024), 2)

        auth_log_path = "/var/log/auth.log"
        if os.path.exists(auth_log_path):
            with open(auth_log_path, "r") as log_file:
                for line in log_file:
                    if "Failed password" in line or "Invalid user" in line:
                        failed_login_attempts += 1
                    if "Firewall alert" in line:
                        firewall_alerts += 1
                    if "from" in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == "from" and i + 1 < len(parts):
                                suspicious_ips.add(parts[i + 1])

        # Generate threat analysis log
        ai_threats.append(f"📡 Network Traffic: {network_traffic_mb} MB")
        ai_threats.append(f"⚠️ Failed Login Attempts: {failed_login_attempts}")
        ai_threats.append(f"🛡️ Firewall Alerts: {firewall_alerts}")
        ai_threats.append(f"🚨 Suspicious IPs Count: {len(suspicious_ips)}")

        # Determine Threat Level
        threat_level = "Low"
        if failed_login_attempts > 50 or firewall_alerts > 10 or len(suspicious_ips) > 20:
            threat_level = "High"
        elif failed_login_attempts > 20 or firewall_alerts > 5 or len(suspicious_ips) > 10:
            threat_level = "Medium"

        ai_threats.append(f"🔥 Threat Level: {threat_level}")

        if not ai_threats:
            ai_threats.append("✅ No AI threat indicators found in logs.")

        self.text_area.insert(tk.END, "\n".join(ai_threats) + "\n\n", "green")
        
        self.text_area.see(tk.END)

    def export_system_logs_csv(self):
        """Export collected system logs as a CSV file."""
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")], title="Save System Logs")
        if file_path:
            with open(file_path, mode="w", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(["System Log Data"])
                for line in self.text_area.get("1.0", tk.END).strip().split("\n"):
                    writer.writerow([line])
            messagebox.showinfo("Success", "System Logs exported successfully!")

    def export_threat_data_csv(self):
        """Automatically save AI Threat Data to a CSV file and append new rows each time."""
    
        # Define the fixed CSV file path
        file_path = "/home/kali/Desktop/advanced scanner/threat_data_output/threat_data.csv"  # Change this path as needed

        # Check if file exists to determine if header is needed
        file_exists = os.path.exists(file_path)

        with open(file_path, mode="a", newline="") as file:  # Append mode
            writer = csv.writer(file)

            # Write header only if the file is new
            if not file_exists:
                writer.writerow(["Network Traffic (MB)", "Failed Login Attempts", "Firewall Alerts", "Suspicious IP Count", "Threat Level"])

            # Initialize list before using it
            data_rows = []

            # Extract data from the logs
            lines = self.text_area.get("1.0", "end").strip().split("\n")
  
            for line in lines:
                data_row = [0, 0, 0, 0, "Low"]  # Default values
            
                if "📡 Network Traffic" in line:
                    data_row[0] = float(line.split(": ")[1].split(" MB")[0])
                elif "⚠️ Failed Login Attempts" in line:
                    data_row[1] = int(line.split(": ")[1])
                elif "🛡️ Firewall Alerts" in line:
                    data_row[2] = int(line.split(": ")[1])
                elif "🚨 Suspicious IPs Count" in line:
                    data_row[3] = int(line.split(": ")[1])
                elif "🔥 Threat Level" in line:
                    data_row[4] = line.split(": ")[1]

                data_rows.append(data_row)

            # Ensure data is written
            if data_rows:
                writer.writerows(data_rows)
                messagebox.showinfo("Success ✅", f"AI Threat Data successfully exported to:\n{file_path}")
            else:
                messagebox.showwarning("Warning ⚠️", "No valid data found to export. Please check your input.") 

                

