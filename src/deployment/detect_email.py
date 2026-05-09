import joblib
import numpy as np
import re
import whois
import json
import os
import requests
import base64
import dns.resolver
from datetime import datetime
from bs4 import BeautifulSoup
from src.features.url_analysis import analyze_urls

CACHE_FILE = "domain_cache.json"

class EmailPhishingDetector:
    def __init__(self, model_path="src/models/Support Vector Machine (SVM)_model.pkl", vectorizer_path="src/models/tfidf_vectorizer.pkl"):
        self.model = joblib.load(model_path)
        self.vectorizer = joblib.load(vectorizer_path)
        self.cache = self._load_cache()
        self.virusTotal_api_key = os.getenv("VT_API_KEY", "627bf46587e5f39b7f20ac60104ad1baf9973cf82f37d2242efdff544bee9929")
        
        self.top_domains = self._load_top_domains()

    def _load_cache(self):
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, "r") as f:
                    return json.load(f)
            except: return {}
        return {}

    def _save_cache(self):
        with open(CACHE_FILE, "w") as f:
            json.dump(self.cache, f)

    def verify_spf(self, domain, sender_ip):
        if not sender_ip: return False
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for txt_record in answers:
                record = txt_record.to_text().lower()
                if "v=spf1" in record:
                    if sender_ip in record or "include:" in record:
                        return True
        except: pass
        return False

    def check_auth_headers(self, headers_raw):
        results = {"dkim": False, "dmarc": False}
        if not headers_raw: return results
        if re.search(r'dkim=pass', headers_raw, re.I): results["dkim"] = True
        if re.search(r'dmarc=pass', headers_raw, re.I): results["dmarc"] = True
        return results

    def get_vt_reputation(self, url):
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": self.virusTotal_api_key}
        try:
            response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=5)
            if response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                return stats.get('malicious', 0) + stats.get('suspicious', 0)
        except: pass
        return 0

    def _load_top_domains(self):
        path = "tranco_VQWQN.csv"
        if os.path.exists(path):
            try:
                import pandas as pd
                # Only load the top 50,000 rows to keep it fast
                # Tranco CSV format is usually: Rank, Domain
                df = pd.read_csv(path, header=None, nrows=50000) 
                return set(df[1].str.lower().tolist())
            except Exception as e:
                print(f"Error loading reputation data: {e}")
        return set()
    
    def get_domain_age(self, domain):
        if domain in self.cache and "age" in self.cache[domain]:
            return self.cache[domain]["age"]
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list): creation_date = creation_date[0]
            if creation_date:
                age_days = (datetime.now() - creation_date).days
                if domain not in self.cache: self.cache[domain] = {}
                self.cache[domain]["age"] = age_days
                self._save_cache()
                return age_days
        except: pass
        return 365 

    def clean_text(self, raw_html): 
        soup = BeautifulSoup(raw_html, "html.parser")
        for element in soup(["script", "style"]): element.decompose()
        return " ".join(soup.get_text().split())    

    def predict(self, text, sender_raw="", headers_raw="", sender_ip="", subject=""):
        if not text:
            return {"prediction": "LEGITIMATE", "risk_score": 0.0, "risk_level": "LOW", "threat_indicators": []}
            
        threat_indicators = []

        processed_text = self.clean_text(text)
        tfidf_features = self.vectorizer.transform([processed_text])
        
        decision_score = self.model.decision_function(tfidf_features)[0]
        text_risk = 1 / (1 + np.exp(-decision_score))

        sender_risk = 0.0
        email_addr = re.search(r'<(.*?)>', sender_raw).group(1) if '<' in sender_raw else sender_raw
        domain = email_addr.split('@')[-1].lower()
        
        # Check if domain or its parent (e.g., email.vidangel.com -> vidangel.com) is in Tranco
        is_reputable = False
        if domain in self.top_domains:
            is_reputable = True
        else:
            # Check if the base domain (last two parts) is in the top domains
            parts = domain.split('.')
            if len(parts) > 2:
                base_domain = ".".join(parts[-2:])
                if base_domain in self.top_domains:
                    is_reputable = True

        auth_status = self.check_auth_headers(headers_raw)
        spf_valid = self.verify_spf(domain, sender_ip)
        domain_age = self.get_domain_age(domain)

        if is_reputable:
            # If it's a known brand and passes auth, it's almost certainly legit
            if auth_status["dkim"] and auth_status["dmarc"] and spf_valid:
                sender_risk = -0.45 
            else:
                # If it's a known brand but has minor auth issues (like VidAngel in image_016df4.jpg)
                # give it a small trust bonus instead of a penalty.
                sender_risk = -0.15 
        else:
            # Existing logic for unknown domains
            if domain_age <= 60: sender_risk += 0.5 
            if not spf_valid: sender_risk += 0.4

            local_part = email_addr.split('@')[0]
            if len(local_part) > 8 and not any(v in local_part for v in 'aeiou'):
                sender_risk += 0.30

        url_stats = analyze_urls(text)
        url_risk = 0.0
        
        urls_to_check = re.findall(r'https?://[^\s)>"\]]+', text)
        for url in urls_to_check:
            if "storage.googleapis.com" in url or "blob.core.windows.net" in url:
                url_risk += 0.5

                threat_indicators.append({
                    "tech": "T1566.002",
                    "name": "Cloud-Hosted Phish",
                    "desc": "Hosting phishing content on reputable cloud storage (Google/Azure) to bypass filters."
                })
            
            hits = self.get_vt_reputation(url)
            if hits > 0:
                url_risk += 0.6

        if len(urls_to_check) > 3:
            url_risk += 0.2
        
        if url_stats["has_ip_url"]: url_risk += 0.5
        if url_stats["url_count"] > 5: url_risk += 0.2
        url_risk = min(url_risk, 1.0)

        if text_risk < 0.05:
            sender_risk = min(sender_risk, 0.1)
            url_risk = min(url_risk, 0.1)

        # Brand Alignment Check
        subject_lower = subject.lower()
        brand_name = domain.split('.')[0]
        if is_reputable and brand_name in subject_lower:
            # Subject matches verified sender domain
            sender_risk -= 0.15

        # DYNAMIC WEIGHTING BASED ON REPUTATION
        # DYNAMIC WEIGHTING BASED ON REPUTATION
        if is_reputable and auth_status["dkim"] and auth_status["dmarc"] and spf_valid:
            # Identity is 100% verified for a top domain.
            # Drop the text risk significantly so it doesn't cause false positives.
            adjusted_text_risk = text_risk * 0.15 
            combined_score = (
                (adjusted_text_risk * 0.10) + 
                (sender_risk * 0.70) + 
                (url_risk * 0.20)
            )
        elif is_reputable:
            combined_score = (
                (text_risk * 0.20) + 
                (sender_risk * 0.60) + 
                (url_risk * 0.20)
            )
        else:
            # Standard weighting for unknown or unverified senders
            # If the domain is UNKNOWN, text risk is much more dangerous
            # Especially if text_risk is high (Social Engineering Lure)
            text_weight = 0.70 if text_risk > 0.60 else 0.50

            combined_score = (
                (text_risk * text_weight) + 
                (sender_risk * 0.10) + 
                (url_risk * (0.90 - text_weight)) 
            )

        combined_score = max(0.0, min(1.0, combined_score))
        prediction = "PHISHING" if combined_score >= 0.49 else "LEGITIMATE"

        if not spf_valid and sender_risk > 0:
            threat_indicators.append({
                "tech": "T1566", 
                "name": "Phishing", 
                "desc": "Failed SPF/Identity verification."
            })

        if url_risk > 0.4:
            threat_indicators.append({
                "tech": "T1566.002", 
                "name": "Spearphishing Link", 
                "desc": "Suspicious URL detected."
            })

        if text_risk > 0.65:
            threat_indicators.append({
                "tech": "T1566.001", 
                "name": "Social Engineering Lure", 
                "desc": "High linguistic risk detected: Text matches patterns for financial/urgency lures."
            })

        return {
            "prediction": prediction,
            "risk_score": round(float(combined_score), 2),
            "risk_level": self.get_risk_level(combined_score),
            "auth_results": {"spf": spf_valid, "dkim": auth_status["dkim"], "dmarc": auth_status["dmarc"]},
            "threat_indicators": threat_indicators, 
            "analysis_details": {           
                "text_risk": round(float(text_risk), 2),    
                "sender_risk": round(float(max(0.0, sender_risk)), 2),
                "url_risk": round(float(url_risk), 2)
            }
        }

    def get_risk_level(self, score):
        if score <= 0.34: return "LOW"
        elif score <= 0.49: return "MEDIUM"
        elif score <= 0.60: return "HIGH"
        else: return "CRITICAL"