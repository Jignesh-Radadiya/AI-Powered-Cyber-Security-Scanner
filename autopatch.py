### autopatch.py - Advanced Smart Auto-Patching System ###



import tkinter as tk
from tkinter import messagebox, scrolledtext
import subprocess
import json
import time
import requests
import tempfile
import threading
import tkinter.simpledialog

# AI Patch Intelligence (remains unchanged)
def ai_patch_intelligence(vulnerabilities):
 #   print("DEBUG: Received vulnerabilities ->", vulnerabilities)
    if isinstance(vulnerabilities, list):
        try:
            vulnerabilities = dict(vulnerabilities)
        except ValueError:
       #    print("❌ Error: Unable to convert list to dictionary. Check data format.")
            return {}
    if not isinstance(vulnerabilities, dict):
     #   print(f"❌ Error: Expected dict, but got {type(vulnerabilities)}")
        return {}
    
    analysis = {}
  #  for package, issue in vulnerabilities.items():
    for package in vulnerabilities.keys():
        analysis[package] = f"AI suggests: Urgent update for {package}."
    return analysis

# Check vulnerabilities (remains unchanged)
def check_vulnerabilities():
    vulnerabilities = {}
    try:
        result = subprocess.run(["apt", "list", "--upgradable"], capture_output=True, text=True)
        lines = result.stdout.split("\n")
        for line in lines:
            if "upgradable" in line:
                package = line.split("/")[0]
                vulnerabilities[package] = "Outdated version detected"
    except Exception as e:
        vulnerabilities["Error"] = str(e)
    return vulnerabilities


                    

# Rollback last patch (remains unchanged)
def rollback_last_patch(gui):
    if messagebox.askyesno("Rollback Patch", "Do you want to rollback the last patch?"):
        gui.output_text_2.insert(tk.END, "⏳ Rolling back...\n")
        try:
            subprocess.run(["sudo", "apt", "autoremove", "--purge", "-y"], check=True)
            gui.output_text_2.insert(tk.END, "✅ Rollback successful.\n")
        except Exception as e:
            gui.output_text_2.insert(tk.END, f"❌ Rollback failed: {str(e)}\n")
    else:
        gui.output_text_2.insert(tk.END, "❌ Rollback cancelled.\n")

# GUI Class (Updated to ask user before applying patches)
class PatchGUI(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#1E1E1E")
        self.pack(fill="both", expand=True)
        
        tk.Label(self, text="🔧 AI-Driven Auto-Patch System", font=("Arial", 16), bg="#1E1E1E", fg="#FFFFFF").pack(pady=10)
        self.status_label = tk.Label(self, text="🔍 Checking vulnerabilities...", font=("Arial", 12), fg="#00BFFF", bg="#1E1E1E")
        self.status_label.pack(pady=5)
        
        self.check_button = tk.Button(self, text="🔎 Scan Vulnerabilities", command=self.show_vulnerabilities, bg="#333333", fg="#FFFFFF", activebackground="#555555")
        self.check_button.pack(pady=5)

        self.patch_button = tk.Button(self, text="🚀 Apply AI-Patch", command=self.run_patch, bg="#008000", fg="#FFFFFF", activebackground="#006400", state="disabled")
        self.patch_button.pack(pady=5)
        
        self.stop_button = tk.Button(self, text="🛑 Stop Patching", command=self.stop_patch, bg="#8B0000", fg="#FFFFFF", activebackground="#FF0000", state="disabled")
        self.stop_button.pack(pady=5)

        self.rollback_button = tk.Button(self, text="⏪ Rollback Last Patch", command=self.run_rollback, bg="#1C86EE", fg="#FFFFFF", activebackground="#1874CD")
        self.rollback_button.pack(pady=5)

        self.package_list = tk.Frame(self, bg="#1E1E1E")
        self.package_list.pack(pady=5)
        
        self.check_vars = {}
        self.patch_process = None

        # First output screen (for vulnerability list)
        self.output_text = scrolledtext.ScrolledText(self, height=15, width=80, font=("Arial", 12),  bg="#2C2C2C", fg="#FFFFFF", insertbackground="white")
        self.output_text.pack(pady=10)
        
        # Second output screen (for showing patching progress)
        self.output_text_2 = scrolledtext.ScrolledText(self, height=10, width=80, font=("Arial", 12), bg="#2C2C2C", fg="#FFFFFF", insertbackground="white")
        self.output_text_2.pack(pady=10)

    def show_vulnerabilities(self):
        """Scans for vulnerabilities and displays them in the first output box before allowing selection"""
        self.output_text.delete("1.0", tk.END)  # Clear previous output
        vulnerabilities = check_vulnerabilities()  # Fetch vulnerability data

        
        if not vulnerabilities:
            self.output_text.insert(tk.END, "✅ No vulnerabilities found!\n")
            self.patch_button.config(state="disabled")
        else:
            self.output_text.insert(tk.END, "⚠️ Found Vulnerabilities:\n\n")
            self.found_vulnerabilities = vulnerabilities  # Store vulnerabilities for next step
            
            for package, details in vulnerabilities.items():
                self.output_text.insert(tk.END, f"📦 {package}: {details}\n")
            
            self.patch_button.config(state="normal")
    

    def run_patch(self):
        """Shows checkboxes for vulnerable packages when Apply AI-Patch is clicked"""
        self.output_text_2.delete("1.0", tk.END)  # Clear second output screen
        self.output_text_2.insert(tk.END, "📌 Select packages to patch:\n")
        

        self.check_vars.clear()  # Reset previous selections

        
        # Create a Select All checkbox
        self.select_all_var = tk.BooleanVar()
        select_all_checkbox = tk.Checkbutton(self.output_text_2, text="Select All", variable=self.select_all_var, command=self.select_all, bg="#1E1E1E", fg="#FFFFFF", selectcolor="#333333")
        self.output_text_2.window_create(tk.END, window=select_all_checkbox)
        self.output_text_2.insert(tk.END, "\n")


        # Show individual package checkboxes inside output screen
        for package in self.found_vulnerabilities.keys():
            var = tk.BooleanVar()
            check = tk.Checkbutton(self.output_text_2, text=package, variable=var, bg="#1E1E1E", fg="#FFFFFF", selectcolor="#333333")
            self.output_text_2.window_create(tk.END, window=check)
            self.output_text_2.insert(tk.END, "\n")
            self.check_vars[package] = var

        # Confirm Update Button inside output screen
        self.confirm_patch_button = tk.Button(self.output_text_2, text="Confirm Update", command=self.confirm_patch, bg="#444444", fg="#FFFFFF", activebackground="#666666")
        self.output_text_2.window_create(tk.END, window=self.confirm_patch_button)
        self.output_text_2.insert(tk.END, "\n")


    def auto_patch(self, selected_packages, patch_all):
        """Runs package updates and logs output in the second screen."""
        self.output_text_2.insert(tk.END, "🚀 Starting AI-powered patching...\n")
        self.output_text_2.see(tk.END)
        self.update_idletasks()

        for package in selected_packages:
            self.output_text_2.insert(tk.END, f"🔄 Patching {package}...\n")
            self.output_text_2.see(tk.END)
            self.update_idletasks()
            
            if patch_all or messagebox.askyesno("Update Package", f"Do you want to update {package}?"):
                try:
                    process = subprocess.Popen(
                        ["sudo", "apt", "install", "--only-upgrade", package, "-y"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )

                    # Read output live
                    for line in iter(process.stdout.readline, ""):
                        self.output_text_2.insert(tk.END, line)
                        self.output_text_2.see(tk.END)
                        self.update_idletasks()

                    process.stdout.close()
                    process.wait()

                    if process.returncode == 0:
                        self.output_text_2.insert(tk.END, f"✅ {package} updated successfully!\n")
                    else:
                        self.output_text_2.insert(tk.END, f"❌ Failed to update {package}.\n")
                except Exception as e:
                    self.output_text_2.insert(tk.END, f"❌ Error updating {package}: {str(e)}\n")

        self.output_text_2.insert(tk.END, "✅ Patching Completed!\n")
        self.patch_button.config(state="normal")
        
        
    def select_all(self):
        """Selects or deselects all checkboxes when 'Select All' is clicked."""
        state = self.select_all_var.get()
        for var in self.check_vars.values():
            var.set(state)

    def confirm_patch(self):
        """Processes selected packages and asks for confirmation before updating."""
        selected_packages = [pkg for pkg, var in self.check_vars.items() if var.get()]
        
        if not selected_packages:
            self.output_text_2.insert(tk.END, "⚠️ No packages selected for patching.\n")
            return

        # Ask for update confirmation
        patch_all = messagebox.askyesno("Confirm", f"Update {len(selected_packages)} selected packages?")
        
        if patch_all:
            threading.Thread(target=self.auto_patch, args=(selected_packages,  patch_all), daemon=True).start()


    

    def run_rollback(self):
        threading.Thread(target=rollback_last_patch, args=(self,), daemon=True).start()
        
    def stop_patch(self):
        if self.patch_process:
            self.output_text_2.insert(tk.END, "🛑 Stopping patch process...\n")
            self.patch_process.terminate()  # Kill the process
            self.patch_process = None
            self.output_text_2.insert(tk.END, "✅ Patching process stopped.\n")
            self.stop_button.config(state="disabled")  # Disable Stop button
            self.patch_button.config(state="normal")  # Re-enable Apply Patch button

# Function to launch the GUI
def open_patch_gui(parent):
    PatchGUI(parent)

