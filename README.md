# 🔥 AI-Powered Advanced Cybersecurity Scanner

🚀 **A Next-Gen Cybersecurity Solution** – AI-powered **vulnerability detection, real-time attack simulation, deep packet inspection, and auto-patching** for **network, web, cloud, and container security**. 

---

## 🎯 Key Features

🔹 **AI-Powered Threat Prediction** – Uses machine learning to forecast potential cyber threats.  
🔹 **Real-Time Attack Simulation (Auto-PenTest)** – AI-driven penetration testing for proactive security assessments.  
🔹 **Hybrid Network & Web Scanner** – Unified scanning for **network, web apps, and APIs**.  
🔹 **Deep Packet Inspection (DPI) with AI** – Detects encrypted traffic anomalies.  
🔹 **AI Chatbot for Security Recommendations** – Provides real-time **remediation guidance**.  
🔹 **Cloud & Container Security Scanning** – Secure **AWS, Azure, GCP, Kubernetes, Docker** environments.  
🔹 **Live Traffic Anomaly Detection** – Behavioral AI monitors real-time threats.  
🔹 **Smart Auto-Patching** – **AI-powered vulnerability detection and automated patching**.  
🔹 **MITRE ATT&CK Integration** – Maps threats to known adversary tactics.  
🔹 **Active Directory (AD) Security Testing** – Detects misconfigurations and privilege escalation attempts.  

---

## 📂 Data Dictionary

🔹 **Scanned Assets**  
📌 *Purpose:* Stores scanned network assets, including **IPs, open ports, services, and system details**.  
📦 *Storage:* JSON, CSV, TXT, Python dictionary.  

🔹 **Detected Vulnerabilities & Exploits**  
📌 *Purpose:* Logs vulnerabilities identified via **AI-powered analysis, Nmap, OpenVAS, and SQLMap**.  
📦 *Storage:* JSON, TXT, CSV, Python dictionary.  

🔹 **Live Network Traffic Anomalies**  
📌 *Purpose:* Logs AI-detected **real-time network anomalies** using Deep Packet Inspection (DPI).  
📦 *Storage:* JSON, TXT, Database.  

🔹 **Web & API Security Reports**  
📌 *Purpose:* Stores scan results for **web apps, APIs, and cloud security**.  
📦 *Storage:* JSON, TXT, CSV, PDF.  

🔹 **AI-Generated Threat Intelligence Reports**  
📌 *Purpose:* Stores **risk assessments, predictive threat models, and security insights**.  
📦 *Storage:* JSON, TXT, PDF.  

🔹 **Active Directory (AD) Security Logs**  
📌 *Purpose:* Logs **AD misconfigurations, privilege escalation attempts, and unauthorized access detections**.  
📦 *Storage:* JSON, TXT, CSV.  

---

## 🛋️ Limitations

🚀 **High Resource Consumption:** AI-powered analysis and real-time DPI require significant CPU and memory.  
🔎 **Encrypted Traffic Challenges:** Detecting threats in encrypted traffic without decryption is limited.  
📈 **False Positives & Negatives:** AI-based anomaly detection needs continuous fine-tuning.  
🔄 **Limited Auto-Patching Scope:** Works only with compatible software and environments.  
🌐 **Cloud API Restrictions:** Some cloud scans may require elevated API permissions.  
👨‍💻 **Advanced Attack Evasion Techniques:** AI-based cyber threats may bypass standard detection.  

---

## 🌐 Future Enhancements

🧠 **AI Model Refinement:** Reduce false positives/negatives using advanced AI techniques.  
🔒 **Encrypted Traffic Analysis:** AI-driven behavioral detection without full decryption.  
🛠 **IoT & Industrial Security Support:** Extend capabilities for IoT and ICS security.  
🕵️ **Dark Web Monitoring:** Integrate external intelligence feeds for proactive defense.  
📊 **Advanced Dashboard & Reporting:** Build a GUI/web-based **real-time security dashboard**.  
🛡 **Auto-Remediation & Response:** Implement **AI-driven threat mitigation**.  
💨 **Cloud & Container Hardening:** AI-based recommendations for **AWS, Azure, GCP, Kubernetes**.  
🔄 **Better Auto-Patching:** Expand to more OS and applications.  

---

## 🛠️ Developed Using:

✅ **Python** – Core Development  
✅ **Tkinter** – GUI Interface  
✅ **Scapy** – Packet Manipulation & Network Scanning  
✅ **Nmap** – Network Discovery & Host Enumeration  
✅ **SQLMap** – SQL Injection Testing  
✅ **Trivy** – Cloud & Container Security Scanning  
✅ **AI-Powered Threat Analysis** – Machine Learning-based Detection  
✅ **Deep Packet Inspection (DPI)** – Traffic Analysis  
✅ **WeasyPrint** – PDF Report Generation  
✅ **Jinja2** – Report Template Rendering  

---

## 📦 Installation & Setup

### 🛠 Prerequisites
✅ **Python 3.8+**  
✅ **pip** package manager  
✅ **Virtual Environment (Recommended)**  
✅ **Docker** (For Wazuh, MISP, or Elastic SIEM integration)  
✅ **Nmap, SQLMap, Metasploit** installed  
✅ **RPC Metasploit Configuration:**  
   - Username: `msf`  
   - Password: `msf`  
   - Server: `127.0.0.1`  
   - Port: `55553`  


### 🛠 Installation Steps

🚀 **Clone the Repository**
```bash
git clone https://github.com/Jignesh-Radadiya/AI-Powered-Cyber-Security-Scanner.git
cd AI-Powered-Cyber-Security-Scanner
```

🛠 **Set Up a Virtual Environment** *(Recommended)*
```bash
python -m venv venv
source venv/bin/activate  # Linux
venv\Scripts\activate    # Windows
```

📥 **Install Dependencies**
```bash
pip install -r requirements.txt
```
🔑 **Set Up OpenAI API Key for Chatbot**
```bash
export OPENAI_API_KEY="Your_Open_AI_Key"  # Linux
set OPENAI_API_KEY="Your_Open_AI_Key"    # Windows
```
▶️ **Run the Scanner**
```bash
python main.py
```

---

## 📚 License
🔹 This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.

---

🚀 **Built with AI & Security in Mind!** 🔐



