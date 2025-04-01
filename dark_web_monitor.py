### Dark_Web_Monitoring ###

import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
import threading
import requests
import socks
import socket
from bs4 import BeautifulSoup
import random
import time
import nltk
from nltk.corpus import stopwords
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline

# Load NLTK stopwords (first-time setup)
nltk.download('stopwords')

# Configure Tor proxy for .onion sites
PROXIES = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050"
}
#socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
#socket.socket = socks.socksocket


# AI Threat Detection Model
class AIThreatDetector:
    def __init__(self):
        self.model, self.vectorizer = self.train_model()

    def train_model(self):
        """Trains a simple AI model to classify dark web content."""
        texts = [
            "Buy stolen credit cards", "Hacked database for sale",
            "Illegal drugs available", "Weapons for sale",
            "Safe marketplace", "Legal forum discussion"
        ]
        #labels = [1, 1, 1, 1, 0, 0]  # 1 = Threat, 0 = Safe
        labels = ["Financial Fraud", "Hacking Services", "Illegal Drugs", "Weapons Trade", "Safe", "Safe"]

        vectorizer = TfidfVectorizer(stop_words=stopwords.words('english'))
        model = make_pipeline(vectorizer, MultinomialNB())
        model.fit(texts, labels)
        return model, vectorizer

    def predict(self, text):
        """Predicts the category of a threat."""
        return self.model.predict([text])[0]

# GUI Class
class DarkWebMonitoringGUI(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.configure(bg="#2E2E2E")
        self.pack(fill="both", expand=True)

        # Title Label
        self.label = tk.Label(self, text="🌐 Dark Web Monitoring", font=("Arial", 16), bg="#2E2E2E", fg="#E0E0E0")
        self.label.pack(pady=10)
        
         # Add Dark Web Site Button
        self.add_site_button = tk.Button(self, text="➕ Add Dark Web Site", font=("Arial", 12), bg="#3A3F44", fg="white", command=self.add_dark_web_site)
        self.add_site_button.pack(pady=5)

        # Start Monitoring Button
        self.start_button = tk.Button(self, text="Start Monitoring", font=("Arial", 12), bg="#008000", fg="white", command=self.start_monitoring)
        self.start_button.pack(pady=5)

        # Stop Monitoring Button
        self.stop_button = tk.Button(self, text="Stop Monitoring", font=("Arial", 12), bg="#B22222", fg="white", command=self.stop_monitoring)
        self.stop_button.pack(pady=5)

       

        # Remove Dark Web Site Button
        self.remove_site_button = tk.Button(self, text="❌ Remove Dark Web Site", font=("Arial", 12), bg="#8B0000", fg="white", command=self.remove_dark_web_site)
        self.remove_site_button.pack(pady=5)
        
        # Clear Output Button
        self.clear_button = tk.Button(self, text="🧹 Clear Output", font=("Arial", 12), bg="#444444", fg="white", command=self.clear_output)
        self.clear_button.pack(pady=5)

        # Log Display Box
        self.log_box = scrolledtext.ScrolledText(self, height=15, width=80, bg="#1C1C1C", fg="#00FF00", insertbackground="white", font=("Arial", 12))
        self.log_box.pack(pady=10)

        # Dark Web Sites List
        self.dark_web_sites = []

        # AI Threat Detector
        self.ai_detector = AIThreatDetector()

        # Monitoring Status
        self.monitoring = False

    def log(self, message):
        """Displays logs in the GUI."""
        self.log_box.insert(tk.END, f"{message}\n")
        self.log_box.yview(tk.END)  # Auto-scroll

    def add_dark_web_site(self):
        """Allows the user to manually add a dark web site URL."""
        new_site = simpledialog.askstring("Add Dark Web Site", "Enter .onion URL:")
        if new_site and new_site.endswith(".onion"):
            self.dark_web_sites.append(new_site)
            self.log(f"✅ Added {new_site}")
        else:
            messagebox.showerror("Invalid URL", "Please enter a valid .onion URL.")

    def remove_dark_web_site(self):
        """Allows the user to remove a dark web site URL."""
        if not self.dark_web_sites:
            messagebox.showwarning("No Sites", "No dark web sites to remove.")
            return

        remove_site = simpledialog.askstring("Remove Dark Web Site", "Enter .onion URL to remove:")
        if remove_site in self.dark_web_sites:
            self.dark_web_sites.remove(remove_site)
            self.log(f"❌ Removed {remove_site}")
        else:
            messagebox.showerror("Not Found", "URL not found in the list.")

    def start_monitoring(self):
        """Starts dark web monitoring in a separate thread."""
        if not self.dark_web_sites:
            messagebox.showwarning("No Sites", "Please add at least one .onion site.")
            return

        self.log("🚀 Starting Dark Web Monitoring...")
        self.monitoring = True
        threading.Thread(target=self.scan_dark_web, daemon=True).start()

    def stop_monitoring(self):
        """Stops monitoring."""
        self.log("⛔ Stopping Monitoring...")
        self.monitoring = False

    def scan_dark_web(self):
        """Scans dark web sites for threats."""
        if not self.dark_web_sites:
            self.log("⚠️ Error: No dark web sites available for scanning.")
            return
        session = requests.Session()
        session.proxies = PROXIES
        
        while self.monitoring:
            site = random.choice(self.dark_web_sites)
            self.after(0, self.log, f"🔍 Scanning: {site}")

            try:
                response = requests.get(site, proxies=PROXIES, timeout=120)
                soup = BeautifulSoup(response.text, "html.parser")
                text = soup.get_text()

                # AI Threat Detection
               # threat_level = self.ai_detector.predict(text)
                threat_category = self.ai_detector.predict(text)
               # if threat_level == 1:
                if threat_category != "Safe":
                  #  self.log("⚠️ Threat detected! Possible illegal content found.")
                    self.log(f"⚠️ Threat detected: {threat_category}")
                else:
                    self.log("✅ No threats detected.")

            except Exception as e:
                self.log(f"❌ Failed to accessing {site}: {e}")

            time.sleep(5)  # Wait before scanning another site
            
            
    def clear_output(self):
        """Clears the log output."""
        self.log_box.delete('1.0', tk.END)
        
            
if __name__ == "__main__":
    root = tk.Tk()
    root.title("Dark Web Monitoring Tool")
    app = DarkWebMonitoringGUI(root)
    root.mainloop()

