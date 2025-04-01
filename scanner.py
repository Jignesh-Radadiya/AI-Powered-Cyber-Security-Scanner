import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import subprocess
import threading
import datetime
import json
import csv
import socket
import re
import os

def apply_dark_theme(widget):
    """Applies a dark theme to the given Tkinter widget."""
    try:
        if isinstance(widget, (tk.Label, tk.Button, tk.Entry, tk.Text, scrolledtext.ScrolledText)):
            widget.configure(bg="#2E2E2E", fg="white", insertbackground="white")
        elif isinstance(widget, scrolledtext.ScrolledText):
            widget.configure(bg="#1E1E1E", fg="lime", insertbackground="white")  # Green text for output
        elif isinstance(widget, tk.Frame):
            widget.configure(bg="#2E2E2E")
    except tk.TclError:
        pass  # Ignore errors for widgets that don't support certain options

    for child in widget.winfo_children():
        apply_dark_theme(child)

def update_progress(progress_bar, value):
    """Updates the progress bar with the given value."""
    progress_bar['value'] = value
    progress_bar.update_idletasks()

def run_with_progress(target_function, args, progress_bar):
    """Runs a function in a separate thread while updating the progress bar."""
    def wrapper():
        update_progress(progress_bar, 10)
        target_function(*args)
        update_progress(progress_bar, 100)
    
    threading.Thread(target=wrapper).start()

def get_device_ip():
    """Detects the current device's local IP address."""
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        return local_ip
    except Exception as e:
        return f"Error: {e}"

def detect_and_scan_live_host():
    """Detects the live host's IP and performs an Nmap scan."""
    target_ip = get_device_ip()
    if target_ip.startswith("Error"):
        messagebox.showerror("Error", "Could not detect device IP.")
        return
    threading.Thread(target=nmap_scan, args=(target_ip, output_text, result_table, table_frame, scan_data_storage)).start()


def save_report(scan_data_storage):
    """Saves the scan results in CSV, JSON, or TXT format based on user selection."""
    if not scan_data_storage:
        messagebox.showerror("Error", "No scan data to save!")
        return

    # Ask user to select file type explicitly
    file_path = filedialog.asksaveasfilename(
        title="Save Report As",
        filetypes=[("CSV File", "*.csv"), ("JSON File", "*.json"), ("Text File", "*.txt")],
        defaultextension=""
    )

    if not file_path:  
        return  # User canceled the save dialog

    # Ensure correct extension is added (if missing)
    if not file_path.endswith((".csv", ".json", ".txt")):
        messagebox.showerror("Error", "Please select a valid file type!")
        return

    file_extension = os.path.splitext(file_path)[1].lower()
    print(f"Saving File: {file_path}, Detected Extension: {file_extension}")  # Debugging

    try:
        if file_extension == ".csv":
            with open(file_path, "w", newline="") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["Target", "Port", "Service", "OS", "Vulnerabilities"])
                for entry in scan_data_storage:
                    writer.writerow([
                        entry.get("Target", ""), 
                        entry.get("Port", ""), 
                        entry.get("Service", ""), 
                        entry.get("OS", ""), 
                        entry.get("Vulnerabilities", "")
                    ])
            messagebox.showinfo("Success", f"CSV report saved: {file_path}")

        elif file_extension == ".json":
            with open(file_path, "w", encoding="utf-8") as jsonfile:
                json.dump(scan_data_storage, jsonfile, indent=4)
            messagebox.showinfo("Success", f"JSON report saved: {file_path}")

        elif file_extension == ".txt":
            with open(file_path, "w", encoding="utf-8") as txtfile:
                for entry in scan_data_storage:
                    txtfile.write(f"Target: {entry.get('Target', '')}\n")
                    txtfile.write(f"Port: {entry.get('Port', '')}\n")
                    txtfile.write(f"Service: {entry.get('Service', '')}\n")
                    txtfile.write(f"OS: {entry.get('OS', '')}\n")
                    txtfile.write(f"Vulnerabilities: {entry.get('Vulnerabilities', '')}\n")
                    txtfile.write("-" * 60 + "\n")
            messagebox.showinfo("Success", f"TXT report saved: {file_path}")

        else:
            messagebox.showerror("Error", "Unsupported file format!")

    except Exception as e:
        messagebox.showerror("Error", f"Failed to save file: {e}")
        
        
def sql_injection_test(target_url, output_text, scan_data_storage, progress_bar):
    """Tests for SQL Injection vulnerabilities and updates the progress bar."""
    
    if not target_url:
        messagebox.showerror("Error", "Please enter a target URL!")
        return

    output_text.insert(tk.END, f"🔍 Running SQL Injection Test on {target_url}...\n", "green")
    output_text.insert(tk.END, "-" * 60 + "\n", "green")
    output_text.yview(tk.END)
    
    update_progress(progress_bar, 10)  # Start progress

    try:
        sqlmap_cmd = ["sqlmap", "-u", target_url, "--batch", "--risk=3", "--level=5", "--dbs"]
        process = subprocess.Popen(sqlmap_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        sql_vulnerabilities = []
        update_progress(progress_bar, 30)

        for line in process.stdout:
            output_text.insert(tk.END, line, "green")
            output_text.yview(tk.END)
            if "possible SQL injection" in line or "database" in line:
                sql_vulnerabilities.append(line.strip())
                
            update_progress(progress_bar, min(progress_bar["value"] + 5, 90))  # Gradually increase

        process.wait()
        update_progress(progress_bar, 95)

        vuln_details = "\n".join(sql_vulnerabilities) if sql_vulnerabilities else "No vulnerabilities found"
        scan_data_storage.append({"Target": target_url, "Scan Type": "SQL Injection", "Details": vuln_details})

        output_text.insert(tk.END, f"✅ SQL Injection Scan Completed.\n", "green")
    except Exception as e:
        output_text.insert(tk.END, f"❌ Error: {e}\n")
        
    finally:
        update_progress(progress_bar, 100)  # Ensure full completion

def nmap_scan(target_ip, output_text, result_table, table_frame, scan_data_storage, progress_bar):
    """Performs an advanced Nmap scan."""
    update_progress(progress_bar, 20)
    output_text.insert(tk.END, f"🔍 Scanning {target_ip} for vulnerabilities...\n", "green")
    output_text.insert(tk.END, "-" * 60 + "\n", "green")
    output_text.yview(tk.END)

    try:
        nmap_cmd = ["nmap", "-A", "-p-", "--script=vuln", target_ip]
        process = subprocess.Popen(nmap_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        scan_data = []
        os_info = "Unknown"
        open_ports = []
        vulnerabilities = []

        for line in process.stdout:
            output_text.insert(tk.END, line, "green")
            output_text.yview(tk.END)
            update_progress(progress_bar, min(progress_bar["value"] + 5, 90))

            if "OS details:" in line:
                os_info = line.split("OS details:")[-1].strip()

            port_match = re.match(r"(\d{1,5})/tcp\s+open\s+([\w-]+)", line)
            if port_match:
                open_ports.append(port_match.groups())

            if "CVE-" in line:
                vulnerabilities.append(line.strip())

        process.wait()
        update_progress(progress_bar, 95)

        table_frame.pack(fill=tk.BOTH, expand=True)
        result_table.delete(*result_table.get_children())

        for port, service in open_ports:
            vuln_text = "\n".join(vulnerabilities) if vulnerabilities else "No known vulnerabilities"
            result_table.insert("", "end", values=(target_ip, port, service, os_info, vuln_text))
            scan_data.append({"Target": target_ip, "Scan Type": "Nmap Scan", "Details": vuln_text})

        scan_data_storage.extend(scan_data)
        output_text.insert(tk.END, f"✅ Nmap Scan Completed.\n", "green")
    except Exception as e:
        output_text.insert(tk.END, f"❌ Error: {e}\n")
    finally:
        update_progress(progress_bar, 100)

def clear_output(output_text, result_table, table_frame):
    """Clears the output text and hides the result table."""
    output_text.delete("1.0", tk.END)
    result_table.delete(*result_table.get_children())
    table_frame.pack_forget()

def open_scanner_gui(parent_frame):
    """Creates and integrates the scanner GUI inside the main application window."""
    scanner_frame = tk.Frame(parent_frame, bg="#2E2E2E")
    scanner_frame.pack(fill=tk.BOTH, expand=True)

    tk.Label(scanner_frame, text="🔍 Advanced Scanner", font=("Arial", 14, "bold"), bg="#2E2E2E", fg="white").pack(pady=5)

    tk.Label(scanner_frame, text="🎯 Target IP / Website URL:", bg="#2E2E2E", fg="white").pack()
    target_entry = tk.Entry(scanner_frame, width=50, bg="#4E4E4E", fg="white", insertbackground="white")
    target_entry.pack(pady=2)

    output_text = scrolledtext.ScrolledText(scanner_frame, height=20, width=90, bg="#1E1E1E", fg="lime", insertbackground="white")
    output_text.tag_configure("green", foreground="lime")
    output_text.pack(pady=5)
    
    progress_bar = ttk.Progressbar(scanner_frame, orient="horizontal", length=400, mode="determinate")
    progress_bar.pack(pady=5)

    table_frame = tk.Frame(scanner_frame, bg="#2E2E2E")
    columns = ("Target", "Port", "Service", "OS", "Vulnerabilities")
    result_table = ttk.Treeview(table_frame, columns=columns, show="headings", height=5)
    for col in columns:
        result_table.heading(col, text=col, anchor="center")
        result_table.column(col, width=150, anchor="center")
    result_table.pack(fill=tk.BOTH, expand=True)

    btn_frame = tk.Frame(scanner_frame, bg="#2E2E2E")
    btn_frame.pack(pady=5)  # ✅ Keep btn_frame outside any function

    scan_data_storage = []

    def run_nmap_scan():
        """Runs the Nmap scan and stores the result."""
        scan_data_storage.clear()
        threading.Thread(target=nmap_scan, args=(target_entry.get(), output_text, result_table, table_frame, scan_data_storage, progress_bar)).start()

    def run_sql_injection_test():
        """Runs the SQL injection test and stores the result."""
        scan_data_storage.clear()
        threading.Thread(target=sql_injection_test, args=(target_entry.get(), output_text, scan_data_storage, progress_bar)).start()

    def detect_and_scan_live_host():
        """Detects the device IP and runs an Nmap scan."""
        device_ip = get_device_ip()
        target_entry.delete(0, tk.END)
        target_entry.insert(0, device_ip)
        run_nmap_scan()

    # ✅ Define buttons **once**, do not recreate `btn_frame`
    tk.Button(btn_frame, text="🛡 Nmap Scan", command=run_nmap_scan, bg="#4E4E4E", fg="white").grid(row=0, column=0, padx=5, pady=5)
    tk.Button(btn_frame, text="🔍 Live Host Scan", command=detect_and_scan_live_host, bg="#4E4E4E", fg="white").grid(row=0, column=1, padx=5, pady=5)
    tk.Button(btn_frame, text="💉 SQL Injection Test", command=run_sql_injection_test, bg="#4E4E4E", fg="white").grid(row=0, column=2, padx=5, pady=5)
    tk.Button(btn_frame, text="💾 Save Report", command=lambda: save_report(scan_data_storage), bg="#4E4E4E", fg="white").grid(row=0, column=3, padx=5, pady=5)
    tk.Button(btn_frame, text="❌ Clear Output", command=lambda: clear_output(output_text, result_table, table_frame), bg="#4E4E4E", fg="white").grid(row=0, column=4, padx=5, pady=5)
    
    apply_dark_theme(scanner_frame)

    return scanner_frame

