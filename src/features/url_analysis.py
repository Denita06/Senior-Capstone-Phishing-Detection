import re
from urllib.parse import urlparse


# Common URL shorteners used in phishing
SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd",
    "buff.ly", "ow.ly", "cutt.ly"
]

# Suspicious / low-reputation TLDs often used in phishing
SUSPICIOUS_TLDS = [
    ".zip", ".click", ".top", ".xyz", ".work",
    ".monster", ".gq", ".tk", ".loan", ".cam"
]


def extract_urls(text):
    """Extract all URLs from text."""
    return re.findall(r'https?://[^\s)>"\]]+', text)


def is_ip_address(url):
    """Check if URL uses raw IP instead of domain."""
    return bool(re.match(r'https?://\d+\.\d+\.\d+\.\d+', url))


def get_domain(url):
    """Extract domain from URL."""
    try:
        return urlparse(url).netloc.lower()
    except:
        return ""


def analyze_urls(text):
    """
    Extract phishing-related URL features from email text.
    Returns a feature dictionary.
    """

    urls = extract_urls(text)

    if not urls:
        return {
            "url_count": 0,
            "unique_domains": 0,
            "has_ip_url": 0,
            "has_shortener": 0,
            "has_suspicious_tld": 0,
            "avg_url_length": 0
        }

    domains = [get_domain(u) for u in urls]

    # Feature calculations
    url_count = len(urls)
    unique_domains = len(set(domains))
    has_ip_url = int(any(is_ip_address(u) for u in urls))
    has_shortener = int(any(any(s in d for s in SHORTENERS) for d in domains))
    has_suspicious_tld = int(any(any(tld in u.lower() for tld in SUSPICIOUS_TLDS) for u in urls))
    avg_url_length = sum(len(u) for u in urls) / url_count

    return {
        "url_count": url_count,
        "unique_domains": unique_domains,
        "has_ip_url": has_ip_url,
        "has_shortener": has_shortener,
        "has_suspicious_tld": has_suspicious_tld,
        "avg_url_length": avg_url_length
    }