import os
import re
import requests
from dotenv import load_dotenv
import tkinter as tk
from tkinter import messagebox

# Load the API key securely from .env file
load_dotenv()
API_KEY = os.getenv("SAFE_BROWSING_API_KEY")

if not API_KEY:
    raise Exception("API key not found. Set it in the .env file.")

SAFE_BROWSING_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

# Regex pattern to find URLs in messages
url_pattern = r'https?://[^\s]+'

# Function to check if a URL is unsafe
def check_url_google_safebrowsing(url):
    payload = {
        "client": {
            "clientId": "phishing-detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    try:
        response = requests.post(SAFE_BROWSING_URL, json=payload)
        if response.status_code == 200:
            data = response.json()
            return 'matches' in data  # True if unsafe
        else:
            messagebox.showerror("API Error", f"Google API returned status code {response.status_code}")
            return False
    except requests.RequestException as e:
        messagebox.showerror("Network Error", str(e))
        return False

# Function to handle GUI detection
def scan_message():
    message = entry.get("1.0", tk.END).strip()
    urls = re.findall(url_pattern, message)

    if not urls:
        messagebox.showinfo("Result", "No URLs found in the message.")
        return

    unsafe_urls = []
    for url in urls:
        if check_url_google_safebrowsing(url):
            unsafe_urls.append(url)

    if unsafe_urls:
        result = "⚠️ Unsafe URLs Detected:\n" + "\n".join(unsafe_urls)
    else:
        result = "✅ All URLs are safe."

    messagebox.showinfo("Scan Result", result)

# GUI setup
root = tk.Tk()
root.title("Phishing URL Detector for WhatsApp")

label = tk.Label(root, text="Enter WhatsApp message:")
label.pack(pady=5)

entry = tk.Text(root, height=10, width=50)
entry.pack(padx=10, pady=5)

scan_button = tk.Button(root, text="Scan for Phishing URLs", command=scan_message)
scan_button.pack(pady=10)

root.mainloop()
