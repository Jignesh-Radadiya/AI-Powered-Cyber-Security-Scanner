### dashboard.py ###

import tkinter as tk
from tkinter import ttk
import subprocess
import threading
import time
import queue
import psutil
import random
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import Counter

class LiveDashboard:
    def __init__(self, parent):
        """Initialize the live SIEM dashboard."""
        self.parent = parent
        self.parent.configure(bg="#1E1E1E")  # Dark Mode Background

        # Layout: Graphs on Top, Logs Below
        self.top_frame = tk.Frame(self.parent, bg="#1E1E1E")
        self.top_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.bottom_frame = tk.Frame(self.parent, bg="black")
        self.bottom_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # Graphs Section
        self.init_graphs()

        # Logs Section
        self.log_queue = queue.Queue()
        self.init_logs()
        
        

        # Start Live Updates
        self.start_live_log_monitoring()
        self.update_graphs()


    def init_graphs(self):
        """"Create live updating bar and pie charts with professional styling."""
        self.fig, self.axs = plt.subplots(1, 2, figsize=(10, 4), facecolor="#1E1E1E")
        self.fig.patch.set_facecolor("#1E1E1E")

        for ax in self.axs:
            ax.set_facecolor("#1E1E1E")
            ax.spines["bottom"].set_color("white")
            ax.spines["top"].set_color("white")
            ax.spines["left"].set_color("white")
            ax.spines["right"].set_color("white")
            ax.xaxis.label.set_color("white")
            ax.yaxis.label.set_color("white")
            ax.title.set_color("white")
            ax.tick_params(axis='both', colors='white')

        # Matplotlib Canvas
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.top_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)



    def update_graphs(self):
        """Update charts based on real logs."""
        threat_counts = self.analyze_logs()
        
        # Color Mapping for Threat Categories
        color_map = {
            "failed password": "red",
            "unauthorized access": "orange",
            "firewall": "purple",
            "intrusion detected": "yellow",
            "No Threats Detected": "blue",
            "Log Read Error": "gray"
        }
        
        # Get colors dynamically based on detected threats
        colors = [color_map.get(threat, "gray") for threat in threat_counts.keys()]
        
        # Update Bar Chart
        self.axs[0].clear()
        self.axs[0].bar(threat_counts.keys(), threat_counts.values(), color=colors)
        self.axs[0].set_title("Threat Analysis from Logs", color="white")
        self.axs[0].tick_params(axis='x', colors='white', rotation=0)
        self.axs[0].tick_params(axis='y', colors='white')

        # Update Pie Chart
        self.axs[1].clear()
        self.axs[1].pie(threat_counts.values(), labels=threat_counts.keys(), autopct="%1.1f%%", 
                        colors=colors, textprops={'color': "white"})
        self.axs[1].set_title("Threat Distribution", color="white")

        self.canvas.draw()
        self.parent.after(2000, self.update_graphs)  # Update every 2 sec

        
    def analyze_logs(self):
        """Parse logs and count security threats."""
        threat_keywords = {"failed password": "Failed password", "unauthorized access": "Unauthorized access", "firewall": "Firewall alert", "intrusion detected": "Intrusion detected"}
        log_counts = Counter()
        
        log_files = ["/var/log/syslog", "/var/log/auth.log"]
        
        #if you want to test dashboard than comment out and change path your following path
      #  log_files = ["home/kali/Desktop/ai_scanner_github/dashboard_test/test_logs.log"]  # Using test log file  

        try:
            for log_file in log_files:
                with open(log_file, "r") as file:
                    
                    logs = file.readlines()  # 🔹 Read ALL lines
                  
             #       logs = file.readlines()[-100:]  # Read last 100 lines
                    
              #  with open("/var/log/syslog", "r") as log_file:
               #     logs = log_file.readlines()[-100:]  # Read last 100 lines

            for line in logs:
                for keyword in threat_keywords:
                    if keyword in line.lower():
                        log_counts[keyword] += 1

        except Exception as e:
            log_counts["Log Read Error"] = 1

        return log_counts if log_counts else {"No Threats Detected": 1}

        
    


    def init_logs(self):
        """Create a scrollable log display below graphs."""
        self.log_text = tk.Text(self.bottom_frame, bg="#1E1E1E", fg="lime", font=("Arial", 12, "bold"), wrap="word", height=15)
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)

        # Scrollbar for logs
        self.scrollbar = tk.Scrollbar(self.bottom_frame, command=self.log_text.yview, bg="black")
        self.scrollbar.pack(side="right", fill="y")
        self.log_text.config(yscrollcommand=self.scrollbar.set)

    def start_live_log_monitoring(self):
        """Fetch real-time system logs dynamically."""
        log_thread = threading.Thread(target=self.fetch_logs, daemon=True)
        log_thread.start()
        self.update_logs()

    def fetch_logs(self):
        """Read security logs in real time."""
        try:
            # Linux: Use journalctl or tail -f
            
            #if you want to test dashboard than comment out the below line only and change path your following path
            #process = subprocess.Popen(["tail", "-f", "home/kali/Desktop/ai_scanner_github/dashboard_test/test_logs.log"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            process = subprocess.Popen(["tail", "-f", "/var/log/syslog", "/var/log/auth.log"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Windows: Use Get-WinEvent (uncomment this for Windows)
            # process = subprocess.Popen(["powershell", "-Command", "Get-WinEvent -LogName Security | Select-Object -First 10"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            for line in iter(process.stdout.readline, ''):
                self.log_queue.put(line.strip())

        except Exception as e:
            self.log_queue.put(f"[ERROR] Failed to fetch logs: {e}")

    def update_logs(self):
        """Update logs in the UI."""
        if hasattr(self, "log_text") and self.log_text.winfo_exists():
            while not self.log_queue.empty():
                log_entry = self.log_queue.get()
                timestamp = time.strftime('%Y-%m-%d %H:%M:%S')

                self.log_text.insert("end", f"{timestamp} - {log_entry}\n")
                self.log_text.insert("end", "-" * 80 + "\n", "separator")
                self.log_text.see("end")

            self.parent.after(3000, self.update_logs)  # Update every 3 sec
        
        
  
# Function to integrate with main.py
def open_dashboard(parent):
    """Launch the live dashboard inside the main app."""
    LiveDashboard(parent)
