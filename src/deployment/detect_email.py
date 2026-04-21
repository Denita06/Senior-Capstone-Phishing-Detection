import joblib
import numpy as np
import re
import whois
import json
import os
from datetime import datetime
from bs4 import BeautifulSoup
from src.features.url_analysis import analyze_urls

# Local cache to prevent WHOIS rate-limiting and speed up execution
CACHE_FILE = "domain_cache.json"

class EmailPhishingDetector:
    def __init__(self, model_path="src/models/ensemble_model.pkl", vectorizer_path="src/models/tfidf_vectorizer.pkl"):
        self.model = joblib.load(model_path)
        self.vectorizer = joblib.load(vectorizer_path)
        self.cache = self._load_cache()
        
    def _load_cache(self):
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, "r") as f:
                return json.load(f)
        return {}

    def _save_cache(self):
        with open(CACHE_FILE, "w") as f:
            json.dump(self.cache, f)

    def get_domain_age(self, domain):
        """Returns domain age in days. Uses cache to avoid redundant API calls."""
        if domain in self.cache:
            return self.cache[domain]

        # Skip WHOIS for known high-authority domains
        trusted_roots = ["google.com", "microsoft.com", "apple.com", "amazon.com", "uber.com", "eventbrite.com"]
        if any(root in domain for root in trusted_roots):
            return 5000 # Return a high number for legacy domains

        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                age_days = (datetime.now() - creation_date).days
                self.cache[domain] = age_days
                self._save_cache()
                return age_days
        except:
            pass
        
        return 30 # Default to 30 days (suspicious) if lookup fails

    def clean_text(self, raw_html):
        soup = BeautifulSoup(raw_html, "html.parser")
        for element in soup(["script", "style"]):
            element.decompose()
        return " ".join(soup.get_text().split())    

    def predict(self, text, sender_raw="", reply_to="", subject=""):
        if not text:
            return {"prediction": "LEGITIMATE", "risk_score": 0.0, "risk_level": "LOW"}
            
        processed_text = self.clean_text(text)
        tfidf_features = self.vectorizer.transform([processed_text])

        # 1. ML Text Risk (30% weight)
        probs = []
        for model in self.model.named_estimators_.values():
            if hasattr(model, "predict_proba"):
                prob = model.predict_proba(tfidf_features)[0][1]
            else:
                prob = 1 / (1 + np.exp(-model.decision_function(tfidf_features)[0]))
            probs.append(prob)
        text_risk = np.mean(probs)

        # 2. Dynamic Sender Analysis (40% weight)
        sender_risk = 0.0
        email_addr = re.search(r'<(.*?)>', sender_raw).group(1) if '<' in sender_raw else sender_raw
        domain = email_addr.split('@')[-1].lower()
        
        domain_age = self.get_domain_age(domain)
        
        # Check for High-Urgency/Threat keywords
        threat_patterns = ["stolen", "blocked", "action required", "unauthorized", "deleted", "hacked"]
        combined_content = (subject + " " + processed_text).lower()
        has_threat = any(word in combined_content for word in threat_patterns)

        # THE STRATEGY: Age is a multiplier for urgency
        if domain_age <= 30 and has_threat:
            sender_risk += 0.85  # Massive spike for new + scary
        elif domain_age <= 60 and has_threat:
            sender_risk += 0.60  # Still very suspicious
        elif domain_age <= 30:
            sender_risk += 0.30  # General caution for brand new domains
            
        # Display Name Spoofing
        display_name = re.sub(r'<.*?>', '', sender_raw).strip().lower()
        if "uber" in display_name and "uber.com" not in domain:
            sender_risk += 0.60

        # 3. URL Risk (30% weight)
        url_stats = analyze_urls(text)
        url_risk = 0.0
        if url_stats["has_ip_url"]: url_risk += 0.6
        if url_stats["has_suspicious_tld"]: url_risk += 0.4
        url_risk = min(url_risk, 1.0)

        # 4. Reputation Buffers
        buffer = 0.0
        if "unsubscribe" in processed_text.lower():
            buffer -= 0.05 # Trust signal for legitimate bulk mail

        # 5. Final Calculation
        combined_score = (
            (text_risk * 0.30) + 
            (sender_risk * 0.50) + 
            (url_risk * 0.20)
        ) + buffer

        combined_score = max(0.0, min(1.0, combined_score))
        
        # Set a professional threshold
        prediction = "PHISHING" if combined_score >= 0.50 else "LEGITIMATE"

        # MITRE ATT&CK Mapping Logic
        threat_indicators = []
        if sender_risk > 0.5:
            threat_indicators.append({"tech": "T1036", "name": "Masquerading", "desc": "Sender domain age or display name mismatch."})
        if url_stats["has_ip_url"] or url_stats["has_suspicious_tld"]:
            threat_indicators.append({"tech": "T1566.002", "name": "Phishing: Spearphishing Link", "desc": "Suspicious URL structures detected."})
        if has_threat:
            threat_indicators.append({"tech": "T1204.001", "name": "User Execution: Malicious Link", "desc": "Urgency/Threat keywords used to elicit clicks."})

        return {
            "prediction": prediction,
            "risk_score": round(float(combined_score), 2),
            "risk_level": self.get_risk_level(combined_score),
            "threat_matrix": threat_indicators,
            "analysis_details": {           
                "text_risk": round(float(text_risk), 2),
                "sender_risk": round(float(sender_risk), 2),
                "url_risk": round(float(url_risk), 2)
            }
        }
    


    def get_risk_level(self, score):
        if score <= 0.39: return "LOW"
        elif score <= 0.60: return "MEDIUM"
        else: return "HIGH"