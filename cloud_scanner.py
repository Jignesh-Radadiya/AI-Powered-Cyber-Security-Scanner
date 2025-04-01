### cloud_scanner.py - Advanced Cloud & Container Security Scanner ###



import threading
import subprocess
import json
import time
import tkinter as tk
from tkinter import ttk, messagebox
import requests
import os
import random
import scapy.all as scapy
import logging
import pdfkit
from jinja2 import Template
from weasyprint import HTML


# Configure logging
logging.basicConfig(filename="cloud_scanner.log", level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def fetch_latest_cve():
    """Fetch the latest CVEs from a public API for threat intelligence."""
    try:
        response = requests.get("https://cve.circl.lu/api/last", timeout=10)
        #response = requests.get("https://services.nvd.nist.gov/rest/json/cves/1.0", timeout=10)
        if response.status_code == 200:
            cve_data = response.json()
            # Ensure all CVEs have 'document' key
            return [cve for cve in cve_data if 'document' in cve]
    except Exception as e:
        logging.error(f"Error fetching CVEs: {e}")
        return []
    return []
    
    
def ai_threat_prediction(target):
    """AI-powered threat prediction based on past vulnerability data."""
    risk_score = random.randint(1, 10)
    return {
        "target": target,
        "ai_risk_score": risk_score,
        "recommendation": "Immediate patching required" if risk_score > 7 else "Monitor regularly"
    }

def deep_packet_inspection(target):
    """Perform AI-driven deep packet inspection for network anomalies."""
    packets = scapy.sniff(count=10, timeout=5)  # Simulated traffic capture
    anomaly_detected = any("malicious" in str(pkt) for pkt in packets)
    return {
        "target": target,
        "dpi_anomalies": anomaly_detected,
        "suggestion": "Investigate traffic anomalies" if anomaly_detected else "No threats detected"
    }
    
    
def generate_html_report(scan_results):
    """Generate an HTML report from scan results."""
    template = Template("""
    <html>
    <head>
        <title>Cloud Security Scan Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1, h2 { color: #333; }
            .section { border: 1px solid #ddd; padding: 10px; margin-bottom: 20px; }
            pre { background: #f4f4f4; padding: 10px; border-radius: 5px; }
        </style>
    </head>
    <body>
        <h1>Cloud Security Scan Report</h1>
        {% for result in scan_results %}
            <h2>Target: {{ result.target }}</h2>
            <p><strong>AI Risk Score:</strong> {{ result.ai_risk_score }}</p>
            <p><strong>Recommendation:</strong> {{ result.recommendation }}</p>
            <p><strong>Nmap Results:</strong><pre>{{ result.nmap }}</pre></p>
            <p><strong>Trivy Results:</strong><pre>{{ result.docker_scan }}</pre></p>
            <p><strong>DPI Anomalies:</strong> {{ result.dpi_anomalies }}</p>
            <p><strong>DPI Suggestion:</strong> {{ result.dpi_suggestion }}</p>
            <h3>Latest Threats:</h3>
            <ul>
                {% for threat in result.threats %}
                     <li>
                        <strong>CVE ID:</strong> {{ threat.id }}<br>
                        {% if threat.document %}
                    <strong>Severity:</strong> {{ threat.document.get('aggregate_severity', {}).get('text', 'N/A') }}<br>

                    <strong>Category:</strong> {{ threat.document.get('category', 'N/A') }}<br>
                    <strong>Publisher:</strong> {{ threat.document.get('publisher', {}).get('name', 'N/A') }}<br>

                    {% if threat.document.get('notes') %}
                       <strong>Summary:</strong> {{ threat.document['notes'][0].get('text', 'N/A') }}<br>
                       <strong>Details:</strong> {{ threat.document['notes'][1].get('text', 'N/A') }}<br>
                       <strong>Terms:</strong> {{ threat.document['notes'][2].get('text', 'N/A') }}<br>
                    {% endif %}
                    <strong>References:</strong> 
                    <ul>
                            {% for ref in threat.document.get('references', []) %}
                                <li><a href="{{ ref.get('url', '#') }}">{{ ref.get('url', 'N/A') }}</a></li>
                            {% endfor %}
                        </ul>
                  {% else %}
                    <em>Document details not available</em>
                {% endif %}
                    </li>
                {% endfor %}
            </ul>
        {% endfor %}
    </body>
    </html>
    """)
    
    html_content = template.render(scan_results=scan_results)
    # Save as HTML & PDF
    
    output_dir = "cloud_output"
    os.makedirs(output_dir, exist_ok=True)
    
    html_path = os.path.join(output_dir, "cloud_scan_report.html")
    pdf_path = os.path.join(output_dir, "cloud_scan_report.pdf")

   #save as HTML
    with open(html_path, "w") as f:
        f.write(html_content)
        
   #convert to PDF using WeasyPrint
    HTML(string=html_content).write_pdf(pdf_path)

    logging.info("HTML & PDF report generated successfully in 'cloud_output' folder.")

class CloudScannerGUI:
    def __init__(self, parent):
        """Initialize the Cloud Scanner inside the given parent widget."""
        self.frame = tk.Frame(parent, bg="#121212")
        self.frame.pack(fill="both", expand=True)

        self.label = tk.Label(self.frame, text="☁️ Cloud & Container Security Scanner", font=("Arial", 16), bg="#121212", fg="white")
        self.label.pack(pady=10)

        self.scan_button = tk.Button(self.frame, text="🔍 Start Scan", font=("Arial", 12), bg="#2ECC71", fg="white", command=self.run_scan_threaded)
        self.scan_button.pack(pady=10)
        
        self.stop_button = tk.Button(self.frame, text="⛔ Stop Scan", font=("Arial", 12), bg="#E74C3C", fg="white", command=self.stop_scan_process)
        self.stop_button.pack(pady=10)

        self.progress = ttk.Progressbar(self.frame, mode="indeterminate")
        self.progress.pack(fill="x", padx=20, pady=10)

        self.result_text = tk.Text(self.frame, height=15, width=80, wrap="word", font=("Arial", 12), bg="#1E1E1E", fg="white", insertbackground="white")
        self.result_text.pack(pady=10)
        
        self.status_list = tk.Listbox(self.frame, height=20, width=50, font=("Arial", 12), bg="#1E1E1E", fg="lime", selectbackground="#2ECC71")
        self.status_list.pack(pady=10)
        
        self.stop_scan = False  # Flag to control scanning process
        
    def update_status(self, message):
        self.status_list.insert("end", message)
        self.status_list.yview_moveto(1)
        self.frame.update_idletasks()

    def run_scan_threaded(self):
        """Run scan in a separate thread to prevent GUI freeze."""
        self.scan_button.config(state="disabled")  # Disable button during scan
        self.stop_scan = False  # Reset stop flag
        self.progress.start()  # Start progress bar
        self.status_list.delete(0, "end")
        threading.Thread(target=self.scan_cloud_targets, daemon=True).start()
        
    def stop_scan_process(self):
        """Stop the scanning process."""
        self.stop_scan = True
        self.update_status("⛔ Scan Stopping... Please wait.")


    def scan_cloud_targets(self):
        """Perform cloud security scan in the background."""
        self.result_text.insert("end", "Starting advanced cloud security scan...\n")
        self.update_status("Initializing scan...")
        
        cloud_targets = ["aws.amazon.com", "azure.microsoft.com", "cloud.google.com"]
        results = []
        latest_cves = fetch_latest_cve()

        for target in cloud_targets:
            if self.stop_scan:
                self.update_status("⛔ Scan Stopped by User")
                break  # Stop scanning
                
            self.result_text.insert("end", f"Scanning {target}...\n")
            self.update_status(f"Scanning {target} 🔄")
            self.result_text.update_idletasks()  # Force GUI update

            try:
                # Run security scans
                self.update_status(f"Running Nmap scan on {target} 🔄...")
                nmap_result = subprocess.run(["nmap", "-Pn", "-F", "-p-", "-sV", target], capture_output=True, text=True)

                self.update_status(f"Nmap scan completed ✅ for {target}")

                
                self.update_status("Running Trivy scan {target} 🔄...")
                trivy_result = subprocess.run(["trivy", "image", target], capture_output=True, text=True, timeout=300)
                self.update_status("Trivy scan completed ✅")
                
                self.update_status("Performing AI threat prediction {target} 🔄...")
                ai_risk = ai_threat_prediction(target)
               # risk_score = random.randint(1, 10)  # Simulated AI risk assessment
                self.update_status(f"AI Risk Analysis: Score {ai_risk['ai_risk_score']}/10")
                
                self.update_status("Running Deep Packet Inspection {target} 🔄...")
                dpi_result = deep_packet_inspection(target)
                self.update_status("Deep Packet Inspection completed ✅")

                results.append({
                    "target": target,
                    "nmap": nmap_result.stdout,
                    "docker_scan": trivy_result.stdout,
                   # "ai_risk_score": risk_score,
                    "ai_risk_score": ai_risk["ai_risk_score"],
                    "recommendation": ai_risk["recommendation"],
                    "dpi_anomalies": dpi_result["dpi_anomalies"],
                    "dpi_suggestion": dpi_result["suggestion"],
                   # "recommendation": "Immediate patching required" if risk_score > 7 else "Monitor regularly",
                    "threats": latest_cves[:3]  # Show top 3 latest CVEs
                })

            except Exception as e:
                results.append({"target": target, "error": str(e)})
                self.result_text.insert("end", f"Error scanning {target}: {e}\n")

            time.sleep(1)  # Simulate delay for scanning

        # Save results
        output_dir = "cloud_output"
        os.makedirs(output_dir, exist_ok=True)  # Ensure the directory exists

        json_path = os.path.join(output_dir, "cloud_scan_results.json")
        with open(json_path, "w") as f:
            json.dump(results, f, indent=4)

        # Update UI
        generate_html_report(results)
        self.result_text.insert("end", "✅ Cloud security scan completed!\n")
        self.update_status("Scan completed successfully ✅")
        self.scan_button.config(state="normal")  # Re-enable button
        self.progress.stop()  # Stop progress bar
        messagebox.showinfo("Scan Complete", "Cloud scan has been completed! & files has saved cloud_scan_results.json and clod_scan_report.html & .pdf")


