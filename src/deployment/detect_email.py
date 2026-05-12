import joblib
import numpy as np
import re
import whois
import json
import os
import requests
import base64
import dns.resolver
import math

from collections import Counter
from datetime import datetime
from bs4 import BeautifulSoup
from src.features.url_analysis import analyze_urls
from Levenshtein import distance as lev_dist
from urllib.parse import urlparse


# -------------------------------------------------------------
# Local cache file used to store previously queried domain data.
# This helps reduce repeated WHOIS lookups and improves speed.
# -------------------------------------------------------------
CACHE_FILE = "domain_cache.json"


class EmailPhishingDetector:
    """
    INITIALIZATION
     Loads:
     - Trained SVM phishing detection model
     - TF-IDF vectorizer
     - Domain age cache
     - VirusTotal API key
     - Top 50k legitimate domains
    
     These resources are initialized once when the detector
     object is created.
    """

    def __init__(
        self,
        model_path="src/models/Support Vector Machine (SVM)_model.pkl",
        vectorizer_path="src/models/tfidf_vectorizer.pkl"
    ):

        # Load trained machine learning model
        self.model = joblib.load(model_path)

        # Load TF-IDF vectorizer used during training
        self.vectorizer = joblib.load(vectorizer_path)

        # Load cached domain information
        self.cache = self._load_cache()

        # Load VirusTotal API key from environment variables
        self.virusTotal_api_key = os.getenv(
            "VT_API_KEY",
            "YOUR_API_KEY"
        )

        # Load top legitimate domains for reputation checks
        self.top_domains = self._load_top_domains()

    """
     CACHE FUNCTIONS
     Loads cached domain information from JSON file.
    
     The cache stores things like such aspreviously calculated domain ages
    
     This avoids repeatedly querying WHOIS servers which can
     be slow or rate-limited.
    """
    def _load_cache(self):

        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, "r") as f:
                    return json.load(f)
            except:
                return {}
        return {}

    """
    Saves updated cache information back to disk.
    Called whenever new domain data is collected.
    """
    def _save_cache(self):

        with open(CACHE_FILE, "w") as f:
            json.dump(self.cache, f)

    """
    SPF / EMAIL AUTHENTICATION

     Verifies SPF (Sender Policy Framework).
    
     SPF helps determine whether the sender IP address is
     authorized to send emails on behalf of the domain.
    
     Returns:
     - True  -> SPF appears valid
     - False -> SPF failed or unavailable
    
     DNS lookups are time-limited to prevent Streamlit from
     freezing during analysis.
    """
    def verify_spf(self, domain, sender_ip):
        if not sender_ip:
            return False
        try:
            resolver = dns.resolver.Resolver()

            # Prevent long DNS wait times
            resolver.lifetime = 2.0
            resolver.timeout = 2.0

            # Query TXT records
            answers = resolver.resolve(domain, 'TXT')

            for txt_record in answers:
                record = txt_record.to_text().lower()
                # Look for SPF policy
                if "v=spf1" in record:
                    # Very lightweight SPF validation
                    if sender_ip in record or "include:" in record:
                        return True
        except Exception:
            pass

        return False

    """
    Checks raw email headers for:
     - DKIM validation
     - DMARC validation
    
     Authentication headers are important because phishing
     emails often fail one or more authentication checks.
    
     Returns:
     {
         "dkim": True/False,
         "dmarc": True/False
     }
    """
    def check_auth_headers(self, headers_raw):
        results = {
            "dkim": False,
            "dmarc": False
        }
        if not headers_raw:
            return results

        # Search for successful DKIM validation
        if re.search(r'dkim=pass', headers_raw, re.I):
            results["dkim"] = True

        # Search for successful DMARC validation
        if re.search(r'dmarc=pass', headers_raw, re.I):
            results["dmarc"] = True

        return results

    """
    VIRUSTOTAL URL REPUTATION

    Queries VirusTotal API for URL reputation.
    
    VirusTotal aggregates results from many antivirus engines.
    
     Returns:
     - Number of engines that marked the URL as:
       malicious or suspicious
     Higher values indicate greater risk.
    """
    def get_vt_reputation(self, url):

        # VirusTotal requires base64 URL encoding
        url_id = base64.urlsafe_b64encode(
            url.encode()
        ).decode().strip("=")

        headers = {
            "x-apikey": self.virusTotal_api_key
        }
        try:
            response = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
                timeout=2.0
            )
            if response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                return (
                    stats.get('malicious', 0) +
                    stats.get('suspicious', 0)
                )
        except:
            pass

        return 0

    """
    DOMAIN ENTROPY / RANDOMNESS
     RULE 2

     Calculates Shannon entropy for a string.
    
     High entropy domains often appear random/generated:
    
     Example:
     xj3kf92-security-login.com
    
     Legitimate domains usually have lower entropy.
    
     Returns:
     - numerical entropy score
    """
    def calculate_entropy(self, text):
        if not text:
            return 0
        
        # Calculate probability of each character
        probabilities = [
            n_x / len(text)
            for x, n_x in Counter(text).items()
        ]
      # Shannon entropy formula
        entropy = -sum(
            p * math.log2(p)
            for p in probabilities
        )
        return entropy
    
    """
    LOOKALIKE DOMAIN DETECTION

     Detects typo-squatted or lookalike domains.
    
     Example:
     micros0ft.com -> microsoft.com
    
     Uses Levenshtein edit distance to compare domains
     against the top 50k legitimate domains.
    
     Returns:
     (True, matched_domain)
     or
     (False, None)
    """
    def check_lookalike(self, domain):

        # Legitimate top domains are ignored
        if domain in self.top_domains:
            return False, None
        
        for top_d in self.top_domains:
            # Only compare domains with similar length
            if abs(len(domain) - len(top_d)) <= 2:
                d = lev_dist(domain, top_d)
                # Small edit distance indicates spoofing
                if 0 < d <= 2:
                    return True, top_d
        return False, None

    """
    OBFUSCATION DETECTION

     Detects suspicious obfuscated strings.
    
     Phishing emails often contain:
     - long encoded payloads
     - random uppercase strings
     - hidden tracking tokens
    
     Example:
     A82JSKDK2930KSJDKS92JSJDKK
    
     Returns:
     - True if multiple suspicious patterns exist
    """
    def check_obfuscation(self, text):
        obfuscated_patterns = re.findall(
            r'[A-Z0-9]{25,}',
            text
        )
        return len(obfuscated_patterns) > 3

    """
    DOMAIN AGE LOOKUP

     Retrieves domain age using WHOIS records.
    
     Newly created domains are commonly used in phishing.
    
     Returns:
     - age in days
    
     If WHOIS lookup fails, defaults to 365 days
     to avoid false positives.
    """
    def get_domain_age(self, domain):
        # Return cached value if available
        if domain in self.cache and "age" in self.cache[domain]:
            return self.cache[domain]["age"]
        try:

            w = whois.whois(domain)
            creation_date = w.creation_date

            # Some WHOIS responses return lists
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                age_days = (
                    datetime.now() - creation_date
                ).days

                # Store in cache
                if domain not in self.cache:
                    self.cache[domain] = {}
                self.cache[domain]["age"] = age_days
                self._save_cache()
                return age_days
        except:
            pass

        return 365

    """
    LINK INTENT ANALYSIS

     Detects mismatches between:
     - displayed link text
     - actual destination domain
    
     Example:
     "Apple Security" -> malicious-domain.ru
    
     This is a common phishing technique.
    
     Returns:
     (
      has_mismatch,
       all_extracted_urls
     )
    """
    def analyze_link_intent(self, raw_html):
        soup = BeautifulSoup(raw_html, "html.parser")

        # Extract all anchor tags
        links = soup.find_all('a', href=True)
        mismatches = 0

        # Save all URLs for dashboard display
        all_urls = [link['href'] for link in links]

        # Known brands commonly impersonated
        known_brands = [
            "apple",
            "cloud",
            "harbor freight",
            "payment",
            "bank",
            "swagbucks"
        ]

        for link in links:
            actual_url = link['href']
            display_text = (
                link.get_text()
                .strip()
                .lower()
            )
            try:
                actual_domain = (
                    urlparse(actual_url)
                    .netloc
                    .lower()
                )
                for brand in known_brands:
                    # Brand mentioned in text
                    # but NOT in destination domain
                    if (
                        brand in display_text and
                        brand not in actual_domain
                    ):
                        mismatches += 1
            except:
                continue
        return mismatches > 0, all_urls

    """
    EMAIL TEXT CLEANING

    Removes TML tags, scripts, and CSS styles
     Converts HTML email into clean readable text for:
     - ML model processing
     - regex analysis
    """
    def clean_text(self, raw_html):
        soup = BeautifulSoup(raw_html, "html.parser")

        # Remove scripts/styles
        for element in soup(["script", "style"]):
            element.decompose()

        # Return cleaned plain text
        return " ".join(soup.get_text().split())

    """
     Core phishing detection pipeline.
    
     Combines:
     - ML classification
     - sender reputation
     - URL analysis
     - authentication checks
     - behavioral heuristics
     - MITRE ATT&CK correlations
    
     Returns:
     - prediction
     - risk score
     - severity level
     - threat indicators
     - URLs
     - detailed scoring breakdown
    """
    def predict(
        self,
        text,
        sender_raw="",
        headers_raw="",
        sender_ip="",
        subject="",
        reply_to=""
    ):

        # If no content exists,
        # automatically classify as legitimate
        if not text:

            return {
                "prediction": "LEGITIMATE",
                "risk_score": 0.0,
                "risk_level": "LOW",
                "threat_indicators": []
            }

        # Stores MITRE ATT&CK detections
        threat_indicators = []

        # Individual risk components
        sender_risk = 0.0
        url_risk = 0.0
        hard_phish_score = 0.0