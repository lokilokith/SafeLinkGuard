# 🛡️ Phishing URL Detector for WhatsApp-like Messages

This is a beginner-friendly cybersecurity project that detects suspicious or malicious URLs from text messages (like WhatsApp) using the **Google Safe Browsing API**.

## 🚀 Setup & Usage

1. Clone the repo or unzip the downloaded zip file
2. Create a `.env` file and add your Google Safe Browsing API key:

```
SAFE_BROWSING_API_KEY=your_api_key_here
```

3. Install dependencies:

```
pip install -r requirements.txt
```

4. Run the script:

```
python safe_detector.py
```

## ⚙️ Dependencies

- Python 3
- requests
- python-dotenv

## 🔒 Security

Your API key is stored in `.env` and should never be committed to version control.
