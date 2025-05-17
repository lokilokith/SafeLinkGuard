import re
import requests
import os
from dotenv import load_dotenv

# Load the API key from .env file
load_dotenv()
API_KEY = os.getenv("SAFE_BROWSING_API_KEY")

if not API_KEY:
    raise Exception("API key not found. Set it in a .env file.")

SAFE_BROWSING_URL = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}'

def extract_urls(text):
    """
    Extract all URLs starting with http or https from the input text.
    Returns a list of URLs.
    """
    url_pattern = r'https?://[^\s]+'
    return re.findall(url_pattern, text)

def check_url_google_safebrowsing(url):
    """
    Check URL against Google Safe Browsing API.
    Returns True if URL is unsafe, else False.
    """
    payload = {
        "client": {
            "clientId": "stark_phishing_detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(SAFE_BROWSING_URL, json=payload)
        if response.status_code == 200:
            data = response.json()
            return 'matches' in data
        else:
            print(f"API Error: {response.status_code}")
            return False
    except requests.RequestException as e:
        print(f"Network error: {e}")
        return False

# Sample WhatsApp-like message text
sample_text = """
Hey, check this out: https://example.com
Also, beware of this suspicious link http://phishingsite.fake/login
And a normal site: https://openai.com
"""

urls = extract_urls(sample_text)

for url in urls:
    if check_url_google_safebrowsing(url):
        print(f"⚠️ Suspicious URL detected (unsafe): {url}")
    else:
        print(f"✅ Safe URL: {url}")
