### main.py ###

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scanner import open_scanner_gui  # Import the scanner function
from ai_threat_prediction import AIThreatPredictionGUI  # Import AI Threat Prediction
from data_collection import DataCollectionApp  # ✅ Import the correct class
#from anomaly_detection import LiveAnomalyDetectionApp  # ✅ Import the Anomaly Detection GUI
from anomaly_detection import AIAnomalyDetector
from cloud_scanner import CloudScannerGUI  # ✅ Import Cloud Scanner GUI
import subprocess
from autopatch import open_patch_gui  # ✅ Import the One-Click AI Auto-Patch function
from autopentest import AIAutoPentest  # ✅ Import PenTest GUI
from dark_web_monitor import DarkWebMonitoringGUI  # ✅ Import Dark Web Monitoring GUI
from ai_chatbot import AdvancedCyberChatbot  # ✅ Import AI Chatbot GUI
from dashboard import LiveDashboard




class MainApplication(tk.Tk):
    """Main GUI for Advanced Cyber Security Scanner."""
    
    def __init__(self):
        super().__init__()

        self.title("🌍Open Source Advanced Cyber Security Scanner")
        self.geometry("1700x800")  # Increased size for better layout
        self.resizable(True, True)
        
      
        
         # 🔹 Title Bar Frame (Top)
        self.title_bar = tk.Frame(self, bg="#2C3E50", height=40)
        self.title_bar.pack(side="top", fill="x")
        
        
        # 🔹 Toggle Button (☰) Inside Title Bar
        self.toggle_btn = tk.Button(
            self.title_bar, text="☰", font=("Arial", 14), bg="#34495E", fg="white",
            relief="flat", command=self.toggle_sidebar
        )
        self.toggle_btn.pack(side="left", padx=10, pady=5)  # Keeps it on the left inside title bar
        
        


        # Main Frame Layout: Sidebar + Content
        self.main_frame = tk.Frame(self, bg="white")
        self.main_frame.pack(fill="both", expand=True)
        

        # Sidebar Frame
        self.sidebar_width = 220
        self.sidebar_visible = True  # Sidebar is initially visible
        self.sidebar = tk.Frame(self.main_frame, bg="#2C3E50", width=self.sidebar_width)
        self.sidebar.pack(side="left", fill="y")


        

        # Sidebar Buttons
        buttons = [
            ("📊 Dashboard", self.show_dashboard),
            ("🛠 Open Scanner", self.open_scanner),
            ("📥 Collect Data", self.open_data_collection), 
            ("🤖 AI Threat Prediction", self.run_ai_threat_prediction),
            ("⚠️ Live Anomaly Detection", self.open_anomaly_detection),
            ("☁️ Cloud Security Scan", self.open_cloud_scanner),
            ("🚀 Open Auto-Patch", self.open_patch_gui),
            ("🛡 Pentest", self.open_pentest),
            ("🌐 Dark Web Monitoring", self.open_dark_web_monitoring),
            ("💬 AI Chatbot", self.open_ai_chatbot),
            ("❌ Exit", self.quit)
        ]
        
        for text, command in buttons:
            btn = tk.Button(self.sidebar, text=text, font=("Arial", 12), bg="#34495E", fg="white", relief="flat", command=command)
            btn.pack(fill="x", pady=10, padx=10)
            

        # Content Area (Where Scanner GUI Will Appear)
        self.content_frame = tk.Frame(self.main_frame, bg="white")
        self.content_frame.pack(side="right", fill="both", expand=True)
        

        # 🔹 Load Dashboard by Default
        self.show_dashboard()

        
    #Toggle Sidebar
    def toggle_sidebar(self):
        """Toggle sidebar visibility."""
        if self.sidebar_visible:
            self.sidebar.pack_forget()
            self.sidebar_visible = False
        else:
            self.sidebar.pack(side="left", fill="y")
            self.sidebar_visible = True
            
   

    def show_dashboard(self):
        """Display the Live Dashboard."""
        self.clear_content()
        LiveDashboard(self.content_frame)  # ✅ Embed the Live Dashboard inside content frame


    def open_scanner(self):
        """Opens the Scanner inside the Main GUI."""
        self.clear_content()
        open_scanner_gui(self.content_frame)  # Open scanner inside content frame
        
    def open_data_collection(self):
        """Opens the Data Collection UI inside Main GUI."""
        self.clear_content()
        DataCollectionApp(self.content_frame)  # Embed data collection GUI

        
    def run_ai_threat_prediction(self):
        """Opens AI Threat Prediction GUI inside main app."""
        self.clear_content()
        AIThreatPredictionGUI(self.content_frame)
        
    def open_anomaly_detection(self):
        """Opens Live Anomaly Detection inside the main GUI."""
        self.clear_content()
        anomaly_detector = AIAnomalyDetector(self.content_frame)  # Open anomaly detection inside content frame

    def open_cloud_scanner(self):
        """Opens the Cloud Security Scanner GUI inside main app."""
        self.clear_content()
        CloudScannerGUI(self.content_frame)  # ✅ Embed the Cloud Scanner GUI inside content frame

    def open_patch_gui(self):
        """Opens the Auto-Patch GUI inside the main app."""
        self.clear_content()
        open_patch_gui(self.content_frame) 
        
    def open_pentest(self):
        """Opens the PenTest GUI inside the main app."""
        self.clear_content()
        AIAutoPentest(self.content_frame)  # ✅ Open PenTest GUI inside content frame
        
        
    def open_dark_web_monitoring(self):
        """Opens the Dark Web Monitoring GUI inside the main app."""
        self.clear_content()
        DarkWebMonitoringGUI(self.content_frame)  # Call the Dark Web GUI inside content_frame
   
    def open_ai_chatbot(self):
        """Opens the AI Chatbot inside the main GUI."""
        self.clear_content()
        AdvancedCyberChatbot(self.content_frame)  # ✅ Open Chatbot inside content frame
   

    def clear_content(self):
        """Clears everything inside the content frame before loading new content."""
        for widget in self.content_frame.winfo_children():
            widget.destroy()
            
            
    def dummy_function(self):
        """Placeholder function for testing."""
        print("Button Clicked")


# Run the Application
if __name__ == "__main__":
    app = MainApplication()
    app.mainloop()
