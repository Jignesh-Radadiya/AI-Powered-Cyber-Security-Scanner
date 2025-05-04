### ai_chatbot.py - Advanced AI Security Assistant ###
 


#import openai
import tkinter as tk
from tkinter import scrolledtext, Entry, Button, filedialog, messagebox
import json
import requests
import threading
import os
import logging
from huggingface_hub import InferenceClient

# Configure logging
logging.basicConfig(filename="chatbot_errors.log", level=logging.ERROR, format="%(asctime)s - %(message)s")

# Load Hugging Face token (optional but recommended for higher rate limits)
hf_token = os.getenv("HUGGINGFACEHUB_API_TOKEN")
if not hf_token:
    print("⚠ WARNING: Hugging Face token not set! You may hit request limits.")

# Initialize Hugging Face client
client = InferenceClient(token=hf_token)



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
        try:
            query_lower = query.lower()
            if "latest cve" in query_lower:
                return self.get_latest_cves()
            elif "pentest" in query_lower or "penetration testing" in query_lower:
                return self.ask_ai(query, role="ethical hacker")
            elif "malware" in query_lower:
                return self.ask_ai(query, role="malware analyst")
            elif "forensics" in query_lower:
                return self.ask_ai(query, role="digital forensics expert")
            elif "tool" in query_lower:
                return self.ask_ai(query, role="cybersecurity tool expert")
            elif "career" in query_lower or "job" in query_lower:
                return self.ask_ai(query, role="cybersecurity mentor")
            else:
                return self.ask_ai(query, role="cybersecurity expert")
        except Exception as e:
            logging.error(f"Error processing response: {str(e)}")
            return f"⚠ Error processing your question: {str(e)}"

    def ask_ai(self, prompt_text, role="cybersecurity expert"):
        try:
            system_prompt = f"<|system|>\nYou are a helpful {role} providing clear, accurate, and actionable cybersecurity advice.\n<|user|>\n{prompt_text}\n<|assistant|>"
            response = client.text_generation(
                prompt=system_prompt,
                model="HuggingFaceH4/zephyr-7b-beta",
                max_new_tokens=500,
                temperature=0.7,
                top_p=0.9
            )
            return response.strip()
        except Exception as e:
            logging.error(f"Error contacting AI model: {str(e)}")
            return f"⚠ Failed to contact AI model: {str(e)}"
            
            
    
    
    
    def get_latest_cves(self, limit=5):
        url = f"https://cve.circl.lu/api/vulnerability/last/{limit}"
    
        try:
            
            
            response = requests.get(url)

            if response.status_code != 200:
                return [f"⚠ Error fetching CVE data: HTTP {response.status_code}"]

            cves = response.json()
            if not isinstance(cves, list):
                return ["⚠ Unexpected response format from API."]
            
                
            results = []
     #       latest_cves = []
        #        f"🔹 **{item['cve']['CVE_data_meta']['ID']}**: {item['cve']['description']['description_data'][0]['value']}"
           #     for item in data["result"]["CVE_Items"][:5]
       #     ]
            
            for item in cves:
                try:
                    cve_id = item.get("cveMetadata", {}).get("cveId", "Unknown ID")
                    cna_data = item.get("containers", {}).get("cna", {})
                    title = cna_data.get("title", "No title available")
                    description = "No description available"
                    if cna_data.get("descriptions"):
                        description = cna_data["descriptions"][0].get("value", description)


                    # Try to get CVSS base score
                    metrics = cna_data.get("metrics", [])
                    score = "N/A"
                    for m in metrics:
                        if "cvssV4_0" in m:
                            score = m["cvssV4_0"].get("baseScore", "N/A")
                            break
                            

                    link = f"https://cve.circl.lu/vuln/{cve_id}"
                    formatted = f"🔹 **{cve_id}** ({score})\n{title}\n📝 {description}\n🔗 {link}"
                    results.append(formatted)

                except Exception as e:
                    results.append(f"⚠ Error parsing CVE entry: {str(e)}")

        #    return result or ["No valid vulnerabilities found."]
             #   latest_cves.append(
                 #   f"🔹 **{cve_id}** ({severity})\n{description}\n🔗 {cve_url}\n"
             #   )




            
            return "\n".join(results) if results else "⚠ No CVEs were parsed successfully."

        except Exception as e:
            logging.error(f"Error fetching CVEs: {str(e)}")
            return f"⚠ Error fetching CVE data: {str(e)}"

 


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

