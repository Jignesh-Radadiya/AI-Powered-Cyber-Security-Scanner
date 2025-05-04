### ai_threat_prediction.py - Advanced Threat Prediction

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.utils import shuffle

class AIThreatPredictionGUI(tk.Frame):
    """GUI for AI Threat Prediction inside the main application."""

    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.configure(bg="#1E1E1E")  # Dark background
        self.pack(fill="both", expand=True)

        self.model = None  # AI Model Placeholder
        self.data = None  # CSV Dataset Placeholder
        self.is_trained = False  # Track if model is trained

        # Define the expected features
        self.feature_names = ["Network Traffic (MB)", "Failed Login Attempts", "Firewall Alerts", "Suspicious IP Count"]

        self.create_widgets()

    def create_widgets(self):
        """Creates the AI Threat Prediction UI."""
        self.clear_frame()

        tk.Label(self, text="🤖 AI Threat Prediction", font=("Arial", 16, "bold"), fg="white", bg="#1E1E1E").pack(pady=10)

        # CSV Upload Button
        upload_btn = tk.Button(self, text="📂 Upload CSV File", font=("Arial", 12), bg="#2980B9", fg="white", command=self.upload_csv)
        upload_btn.pack(pady=10)

        # Train Model Button
        self.train_btn = tk.Button(self, text="🛠 Train AI Model", font=("Arial", 12), bg="#27AE60", fg="white", command=self.train_model, state="disabled")
        self.train_btn.pack(pady=10)

        # Manual Entry Fields
        tk.Label(self, text="🔢 Enter Threat Indicators (If no CSV)", font=("Arial", 12, "bold"), fg="white", bg="#1E1E1E").pack(pady=10)
        self.entries = []

        for feature in self.feature_names:
            frame = tk.Frame(self, bg="#1E1E1E")
            frame.pack(pady=5)

            tk.Label(frame, text=feature, font=("Arial", 12), fg="white", bg="#1E1E1E").pack(side="left", padx=5)
            entry = tk.Entry(frame, font=("Arial", 12), width=10, bg="#333333", fg="lime")
            entry.pack(side="left", padx=5)
            self.entries.append(entry)

        # Predict Button
        self.predict_btn = tk.Button(self, text="🔍 Predict Threat", font=("Arial", 12), bg="#F39C12", fg="white", command=self.manual_train_and_predict, state="normal")
        self.predict_btn.pack(pady=20)

        # Result Label
        self.result_label = tk.Label(self, text="", font=("Arial", 14, "bold"), fg="red", bg="#1E1E1E")
        self.result_label.pack(pady=10)

    def upload_csv(self):
        """Uploads a CSV file and enables training if valid."""
        file_path = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
        if not file_path:
            return

        try:
            self.data = pd.read_csv(file_path)

            # Check if required columns exist
            required_columns = self.feature_names + ["Threat Level"]
            if not all(col in self.data.columns for col in required_columns):
                messagebox.showerror("Error", "CSV file must contain columns: " + ", ".join(required_columns))
                return

            # Ensure the 'Threat Level' column contains only valid values (0, 1, 2)
            if not all(val in [0, 1, 2] for val in self.data["Threat Level"]):
                self.data["Threat Level"] = self.data["Threat Level"].apply(lambda x: x if x in [0, 1, 2] else 0)

            # Fill NaN values with 0 or the column mean (depending on your preference)
            self.data.fillna(0, inplace=True)  # Fills NaNs with 0

            messagebox.showinfo("Success", "CSV file uploaded successfully!")
            self.train_btn.config(state="normal")  # Enable training button

        except Exception as e:
            messagebox.showerror("Error", f"Failed to load CSV: {str(e)}")

    def train_model(self):
        """Trains the AI model using the uploaded CSV dataset."""
        try:
            if self.data is None:
                messagebox.showerror("Error", "Upload a valid CSV file first.")
                return

            X = self.data[self.feature_names]  # Features
            y = self.data["Threat Level"]  # Target

            # Ensure enough data is available for train-test split
            if len(X) < 2:
                messagebox.showerror("Error", "Not enough data for training. Add more samples.")
                return

            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.model.fit(X_train, y_train)

            # Accuracy Check
            y_pred = self.model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
          #  messagebox.showinfo("Training Complete", f"Model trained successfully! Accuracy: {accuracy:.2f}")

            # Calculate threat level distribution
            unique, counts = np.unique(y_pred, return_counts=True)
            threat_distribution = dict(zip(unique, counts))

            # Format threat level output
            threat_levels = {0: "Low", 1: "Medium", 2: "High"}
            threat_message = "\n".join([f"{threat_levels.get(level, 'Unknown')}: {count}" for level, count in threat_distribution.items()])

            # Determine if action is needed
            high_threats = threat_distribution.get(2, 0)
            medium_threats = threat_distribution.get(1, 0)

            if high_threats > 0 or medium_threats > len(y_pred) * 0.5:  # If there are High threats or too many Medium threats
                action_message = "\n⚠️ Action Needed: Investigate potential threats!"
            else:
                action_message = "\n✅ No immediate action required."

            # Show message box with accuracy, threat level distribution, and action recommendation
            messagebox.showinfo("Training Complete", 
                                f"Model trained successfully!\nAccuracy: {accuracy:.2f}\n\n"
                                f"Threat Level Distribution:\n{threat_message}\n{action_message}")


            
            self.is_trained = True  # Mark model as trained
            self.predict_btn.config(state="normal")  # Enable prediction button

        except Exception as e:
            messagebox.showerror("Error", f"Model training failed: {str(e)}")

    def manual_train_and_predict(self):
        """Trains AI model with manual data and makes a prediction automatically."""
        try:
            # Retrieve and convert all manual input entries to float
            feature_values = []
            for entry in self.entries:
                value = entry.get()
                if value == "":  # Ensure no empty input
                    raise ValueError("Please fill in all the fields.")
                feature_values.append(float(value))

            # Convert to DataFrame with correct feature names
            input_data = pd.DataFrame([feature_values], columns=self.feature_names)


            # Train the model if not already trained
            if self.model is None:
                self.model = RandomForestClassifier(n_estimators=200, random_state=42)  # Initialize model
                # Simulate a small dataset (For real-world cases, load actual data)
                num_samples = 600  # Increase training data size
                X_manual = pd.DataFrame({
                    "Network Traffic (MB)": np.concatenate([
                        np.random.randint(0, 150, 200),  # Low threat
                        np.random.randint(151, 300, 200),  # Medium threat
                        np.random.randint(301, 600, 200)  # High threat
                    ]),
                    "Failed Login Attempts": np.concatenate([
                        np.random.randint(0, 10, 200),
                        np.random.randint(11, 40, 200),
                        np.random.randint(41, 200, 200)
                    ]),
                    "Firewall Alerts": np.concatenate([
                        np.random.randint(0, 5, 200),
                        np.random.randint(6, 30, 200),
                        np.random.randint(31, 100, 200)
                    ]),
                    "Suspicious IP Count": np.concatenate([
                        np.random.randint(0, 20, 200),
                        np.random.randint(21, 70, 200),
                        np.random.randint(71, 300, 200)
                    ]),
                })

                y_manual = np.array([0] * 200 + [1] * 200 + [2] * 200)  # 200 Low, 200 Medium, 200 High
             #   np.random.shuffle(y_manual)  # Shuffle labels
                 # Shuffle features and labels together
                X_manual, y_manual = shuffle(X_manual, y_manual, random_state=42)

                
               

                # Feature scaling
                self.scaler = StandardScaler()
                X_manual_scaled = self.scaler.fit_transform(X_manual)
                
                # Train model
                self.model.fit(X_manual_scaled, y_manual.astype(int))  
                self.result_label.config(text="Model trained with realistic data!", fg="green")


               

            # Enable Predict button after training
            self.predict_btn.config(state="normal")  
            
            # Scale input data before prediction
            input_data_scaled = self.scaler.transform(input_data)


            # Make prediction
            predicted_threat = self.model.predict(input_data_scaled)[0]

            # Map prediction to threat level
            threat_levels = {0: "Low", 1: "Medium", 2: "High"}
            predicted_label = threat_levels.get(predicted_threat, "Unknown")

            # Display the result
            self.result_label.config(text=f"Predicted Threat Level: {predicted_label}", fg="blue")


        except ValueError as ve:
            messagebox.showerror("Input Error", f"Invalid input: {ve}")
        except Exception as e:
            messagebox.showerror("Prediction Error", f"An error occurred: {str(e)}")

    def clear_frame(self):
        """Clears all widgets before loading new content."""
        for widget in self.winfo_children():
            widget.destroy()
