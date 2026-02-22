import json
import re
from urllib.parse import urlparse

def load_phishtank_db(filepath="raw_datasets/phishtank/online-valid.json"):
    """Loads PhishTank URLs into a set for fast lookups."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        url_set = {item['url'] for item in data}
        print(f"Successfully loaded {len(url_set)} URLs from PhishTank DB.")
        return url_set
    except FileNotFoundError:
        print(f"Warning: PhishTank DB not found at {filepath}. URL reputation check will be disabled.")
        return set()
    except Exception as e:
        print(f"Error loading PhishTank DB: {e}")
        return set()

def extract_urls(text):
    """Extracts all URLs from a given text string."""
    url_pattern = re.compile(r'https?://[^\s/$.?#].[^\s]*')
    return re.findall(url_pattern, text)

def is_malicious_url(url, malicious_db):
    """Checks if a URL is in the malicious database."""
    return url in malicious_db
