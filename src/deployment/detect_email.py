import joblib
import numpy as np
import re
import whois
import json
import os
import requests
import base64
from datetime import datetime
from bs4 import BeautifulSoup
from src.features.url_analysis import analyze_urls

# Local cache to prevent WHOIS/VT rate-limiting and speed up execution
CACHE_FILE = "domain_cache.json"

class EmailPhishingDetector:
    """
    A hybrid detection engine that uses ML text classification, 
    domain reputation auditing, and external threat intelligence.
    """
    def __init__(self, model_path="src/models/ensemble_model.pkl", vectorizer_path="src/models/tfidf_vectorizer.pkl"):
        # Load the pre-trained ML model and TF-IDF vectorizer
        self.model = joblib.load(model_path)
        self.vectorizer = joblib.load(vectorizer_path)
        self.cache = self._load_cache()
        # API Key for VirusTotal - used to check if links are known-malicious
        self.virusTotal_api_key = os.getenv("VT_API_KEY", "627bf46587e5f39b7f20ac60104ad1baf9973cf82f37d2242efdff544bee9929")
        
    def _load_cache(self):
        """Loads historical domain data to save time and API credits."""
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, "r") as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def _save_cache(self):
        
        with open(CACHE_FILE, "w") as f:
            json.dump(self.cache, f)

    def get_vt_reputation(self, url):
        """
        Queries VirusTotal V3 API to see if a URL has been flagged as malicious by 70+ antivirus engines.
        """
        if self.virusTotal_api_key == "627bf46587e5f39b7f20ac60104ad1baf9973cf82f37d2242efdff544bee9929":
            return 0 # Default if key is invalid or placeholder
        
        # VT V3 requires URL to be base64 encoded without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": self.virusTotal_api_key}
        
        try:
            response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=5)
            if response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                return stats.get('malicious', 0) + stats.get('suspicious', 0)
        except Exception:
            pass
        return 0

    def get_domain_age(self, domain):
        """
        Checks how old a domain is. New domains (under 30 days) are high risk.
        Uses WHOIS protocol.
        """
        if domain in self.cache and "age" in self.cache[domain]:
            return self.cache[domain]["age"]

        # Whitelist for massive, trusted domains to skip WHOIS lookups
        trusted_roots = ["google.com", "microsoft.com", "apple.com", "amazon.com", "uber.com"]
        if any(root in domain for root in trusted_roots):
            return 5000 

        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                age_days = (datetime.now() - creation_date).days
                if domain not in self.cache: self.cache[domain] = {}
                self.cache[domain]["age"] = age_days
                self._save_cache()
                return age_days
        except:
            pass
        
        return 30 # Default to 30 days (suspicious) if lookup fails

    def clean_text(self, raw_html): 
        """Strips HTML for the ML model."""
        soup = BeautifulSoup(raw_html, "html.parser")
        for element in soup(["script", "style"]):
            element.decompose()
        return " ".join(soup.get_text().split())    

    def predict(self, text, sender_raw="", reply_to="", subject=""):
        """
        The core logic: Aggregates ML text risk, Sender reputation, and URL analysis
        into a single risk score and maps it to MITRE ATT&CK techniques.
        """
        if not text:
            return {"prediction": "LEGITIMATE", "risk_score": 0.0, "risk_level": "LOW"}
            
        processed_text = self.clean_text(text)
        tfidf_features = self.vectorizer.transform([processed_text])

        # 1. ML Text Risk (30% weight): Uses the Ensemble model to find phishing keywords/intent
        probs = []
        for model in self.model.named_estimators_.values():
            if hasattr(model, "predict_proba"):
                prob = model.predict_proba(tfidf_features)[0][1]
            else:
                prob = 1 / (1 + np.exp(-model.decision_function(tfidf_features)[0]))
            probs.append(prob)
        text_risk = np.mean(probs)

        # 2. Sender and Reputation Analysis (40% weight): Checks domain age and lookalike branding
        sender_risk = 0.0
        email_addr = re.search(r'<(.*?)>', sender_raw).group(1) if '<' in sender_raw else sender_raw
        domain = email_addr.split('@')[-1].lower()
        
        domain_age = self.get_domain_age(domain)
        
        threat_patterns = ["stolen", "blocked", "action required", "unauthorized", "deleted", "hacked"]
        combined_content = (subject + " " + processed_text).lower()
        has_threat = any(word in combined_content for word in threat_patterns)

        if domain_age <= 30 and has_threat:
            sender_risk += 0.85  
        elif domain_age <= 30:
            sender_risk += 0.40
            
        # Detect Display Name Spoofing (e.g., Sender says "Uber" but email is "scammer@gmail.com")    
        display_name = re.sub(r'<.*?>', '', sender_raw).strip().lower()
        if "uber" in display_name and "uber.com" not in domain:
            sender_risk += 0.60

        # 3. URL and VirusTotal Analysis (30% weight): Checks links for malware/phishing signatures
        url_stats = analyze_urls(text)
        url_risk = 0.0
        flagged_entities = []
        
        # Logic to check first 2 URLs in VT to stay within rate limits
        urls_to_check = re.findall(r'https?://[^\s)>"\]]+', text)[:2]
        vt_total_hits = 0
        for url in urls_to_check:
            hits = self.get_vt_reputation(url)
            if hits > 0:
                vt_total_hits += hits
                flagged_entities.append({"type": "URL", "value": url[:50]+"...", "hits": hits})
        
        if vt_total_hits > 0: url_risk += 0.7
        if url_stats["has_ip_url"]: url_risk += 0.5
        if url_stats["has_suspicious_tld"]: url_risk += 0.3
        url_risk = min(url_risk, 1.0)

        # 4. Final Score Calculation
        combined_score = (
            (text_risk * 0.30) + 
            (sender_risk * 0.40) + 
            (url_risk * 0.30)
        )
        combined_score = max(0.0, min(1.0, combined_score))
        
        prediction = "PHISHING" if combined_score >= 0.50 else "LEGITIMATE"

        # 5. MITRE ATT&CK Mapping: Converts findings into industry-standard security terminology
        threat_indicators = []
        if sender_risk > 0.5:
            threat_indicators.append({"tech": "T1036", "name": "Masquerading", "desc": "Domain age/display name mismatch."})
        if vt_total_hits > 0 or url_stats["has_ip_url"]:
            threat_indicators.append({"tech": "T1566.002", "name": "Spearphishing Link", "desc": "Malicious URL/IP identified."})
        if has_threat:
            threat_indicators.append({"tech": "T1204.001", "name": "User Execution", "desc": "Urgency used to elicit clicks."})
        if "malware" in combined_content or vt_total_hits > 5:
            threat_indicators.append({"tech": "T1566.001", "name": "Spearphishing Attachment/Link", "desc": "High confidence malware signature."})

        return {
            "prediction": prediction,
            "risk_score": round(float(combined_score), 2),
            "risk_level": self.get_risk_level(combined_score),
            "threat_matrix": threat_indicators,
            "flagged_entities": flagged_entities,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "analysis_details": {           
                "text_risk": round(float(text_risk), 2),
                "sender_risk": round(float(sender_risk), 2),
                "url_risk": round(float(url_risk), 2)
            }
        }

    def get_risk_level(self, score):
        if score <= 0.35: return "LOW"
        elif score <= 0.55: return "MEDIUM"
        elif score <= 0.80: return "HIGH"
        else: return "CRITICAL"