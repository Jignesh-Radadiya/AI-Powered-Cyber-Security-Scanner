### ai_chatbot.py - Advanced AI Security Assistant ###
 


import openai
import tkinter as tk
from tkinter import scrolledtext, Entry, Button, filedialog, messagebox
import json
import requests
import threading
import os
import logging

# Configure logging
logging.basicConfig(filename="chatbot_errors.log", level=logging.ERROR, format="%(asctime)s - %(message)s")

# Load API key securely from environment variable
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("⚠ ERROR: OPENAI_API_KEY is not set! Please set it in your environment variables.")

# Initialize OpenAI client
client = openai.OpenAI(api_key=api_key)


class AdvancedCyberChatbot:
    """AI-Powered Cybersecurity Chatbot"""

    def __init__(self, master):
        self.master = master
        self.master.configure(bg="#2E2E2E")
        self.label = tk.Label(self.master, text="Welcome to AI Cyber Chatbot!", font=("Arial", 16), bg="#2E2E2E", fg="#E0E0E0")
        self.label.pack(pady=10)
        

        # Chat Display
        self.chat_area = scrolledtext.ScrolledText(self.master, wrap=tk.WORD, font=("Arial", 12), bg="#1C1C1C", fg="#00FF00", insertbackground="white")
        self.chat_area.pack(padx=10, pady=10, fill="both", expand=True)
        self.chat_area.insert(tk.END, "🤖 **AI Security Assistant:** Hello! Ask me about cybersecurity threats, vulnerabilities, and fixes.\n\n")
        self.chat_area.config(state=tk.DISABLED)

        # User Input Field
        self.input_field = Entry(self.master, font=("Arial", 12), bg="#1C1C1C", fg="white", insertbackground="white")
        self.input_field.pack(pady=10, fill="x", padx=10)
        self.input_field.bind("<Return>", self.get_response)

        # Buttons
        button_frame = tk.Frame(self.master, bg="#2E2E2E")
        button_frame.pack(pady=5)

        self.send_button = Button(button_frame, text="Send", font=("Arial", 12), bg="#008000", fg="white", command=self.get_response)
        self.send_button.grid(row=0, column=0, padx=5)

        self.export_button = Button(button_frame, text="📄 Export Chat", font=("Arial", 12), bg="#444444", fg="white", command=self.export_chat)
        self.export_button.grid(row=0, column=1, padx=5)

        self.clear_button = Button(button_frame, text="🗑 Clear Chat", font=("Arial", 12), bg="#8B0000", fg="white", command=self.clear_chat)
        self.clear_button.grid(row=0, column=2, padx=5)

    def get_response(self, event=None):
        """Handles user input and fetches AI-generated security advice."""
        user_input = self.input_field.get().strip()
        if not user_input:
            return

        # Display user input
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.insert(tk.END, f"🧑‍💻 **You:** {user_input}\n", "user")
        self.chat_area.config(state=tk.DISABLED)
        self.input_field.delete(0, tk.END)

        # Show typing animation
        self.show_typing_animation()

        # Run AI Response Fetching in Background
        thread = threading.Thread(target=self.process_ai_response, args=(user_input,))
        thread.start()

    def show_typing_animation(self):
        """Simulates AI typing for a real-time effect."""
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.insert(tk.END, "🤖 **AI Security Assistant:** _Typing..._\n")
        self.chat_area.config(state=tk.DISABLED)
        self.chat_area.yview(tk.END)

    def process_ai_response(self, user_input):
        """Fetches AI-generated response and updates the chat."""
        ai_response = self.generate_response(user_input)

        # Remove typing animation and add real response
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.delete("end-2l", tk.END)  # Removes "Typing..." text
        self.chat_area.insert(tk.END, f"🤖 **AI Security Assistant:**\n{ai_response}\n\n", "bot")
        self.chat_area.config(state=tk.DISABLED)
        self.chat_area.yview(tk.END)

    def generate_response(self, query):
        """Fetch AI-powered security recommendations, real-time CVE threats, and pentesting insights."""
        if "latest CVE" in query.lower():
            return self.get_latest_cves()
        elif "pentest" in query.lower():
            return self.get_pentest_guidance(query)
        else:
            return self.get_ai_security_advice(query)

    def get_ai_security_advice(self, vulnerability):
        """Fetch AI-powered security recommendations."""
        prompt = f"Provide cybersecurity recommendations for: {vulnerability}. Include best practices, mitigation steps, and security patches."

        try:
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert providing security advice."},
                    {"role": "user", "content": prompt}
                ]
            )
            return response.choices[0].message.content
        except Exception as e:
            logging.error(f"Error retrieving AI advice: {str(e)}")
            return f"⚠ **Error retrieving advice:** {str(e)}"

    def get_latest_cves(self):
        """Fetch latest cybersecurity vulnerabilities (CVE) from NVD."""
        try:
            url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
            response = requests.get(url)

            if response.status_code != 200:
                return f"⚠ **Error fetching CVE data:** HTTP {response.status_code}"

            data = response.json()
            latest_cves = [
                f"🔹 **{item['cve']['CVE_data_meta']['ID']}**: {item['cve']['description']['description_data'][0]['value']}"
                for item in data["result"]["CVE_Items"][:5]
            ]
            return "\n".join(latest_cves)
        except Exception as e:
            logging.error(f"Error fetching CVE data: {str(e)}")
            return f"⚠ **Error fetching CVE data:** {str(e)}"

    def get_pentest_guidance(self, query):
        """Provide AI-guided penetration testing insights."""
        pentest_prompt = f"Explain penetration testing techniques for: {query}. Include step-by-step methods and security countermeasures."

        try:
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are an ethical hacker providing penetration testing guidance."},
                    {"role": "user", "content": pentest_prompt}
                ]
            )
            return response.choices[0].message.content
        except Exception as e:
            logging.error(f"Error retrieving pentest advice: {str(e)}")
            return f"⚠ **Error retrieving pentest advice:** {str(e)}"

    def export_chat(self):
        """Exports chat conversation to a text file."""
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if filename:
            with open(filename, "w") as file:
                file.write(self.chat_area.get("1.0", tk.END))
            messagebox.showinfo("Success", "Chat exported successfully!")

    def clear_chat(self):
        """Clears the chat window."""
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.delete("1.0", tk.END)
        self.chat_area.insert(tk.END, "🤖 **AI Security Assistant:** Chat cleared. Ask a new question!\n\n")
        self.chat_area.config(state=tk.DISABLED)


if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedCyberChatbot(root)
    root.mainloop()

