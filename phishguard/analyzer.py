import re
import ipaddress
from urllib.parse import urlparse
import tldextract

class PhishGuardAnalyzer:
    def __init__(self, target_url: str):
        self.raw_url = target_url.strip()
        self.normalized_url = ""
        self.parsed = None
        self.extracted = None
        self.risk_score = 0
        self.findings = []
        self.risk_level = "Low"

    def analyze(self):
        self._validate_and_normalize()
        if not self.parsed:
            return self.get_report()

        self._check_ip_and_domain()
        self._check_typosquatting()
        self._check_obfuscation_and_keywords()
        self._calculate_risk_level()
        return self.get_report()

    def _validate_and_normalize(self):
        url = self.raw_url
        if not re.match(r'^[a-zA-Z]+://', url):
            url = 'http://' + url
        try:
            parsed = urlparse(url)
            if not parsed.netloc and not parsed.path:
                raise ValueError("Invalid URL structure")
            
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()
            path = parsed.path if parsed.path else "/"
            query = f"?{parsed.query}" if parsed.query else ""
            
            self.normalized_url = f"{scheme}://{netloc}{path}{query}"
            self.parsed = parsed
            self.extracted = tldextract.extract(netloc)
            self.findings.append({"check": "URL Validation", "status": "Passed", "weight": 0, "detail": "URL successfully validated and normalized."})
        except Exception as e:
            self.findings.append({"check": "URL Validation", "status": "Failed", "weight": 50, "detail": f"Malformed URL format: {str(e)}"})
            self.risk_score += 50

    def _check_ip_and_domain(self):
        netloc = self.parsed.netloc.split(':')[0]
        
        try:
            ipaddress.ip_address(netloc)
            self.findings.append({"check": "IP Address Usage", "status": "Suspicious", "weight": 30, "detail": f"URL uses raw IP address ({netloc}) instead of a registered domain name."})
            self.risk_score += 30
        except ValueError:
            subdomain = self.extracted.subdomain
            domain = self.extracted.domain
            
            if len(subdomain.split('.')) > 2:
                self.findings.append({"check": "Deep Subdomain Nesting", "status": "Warning", "weight": 15, "detail": f"Multiple subdomains detected ('{subdomain}'), often used to spoof legitimate brands."})
                self.risk_score += 15
            
            if len(domain) > 25:
                self.findings.append({"check": "Unusually Long Domain", "status": "Warning", "weight": 10, "detail": f"Domain name length ({len(domain)} chars) is unusually long."})
                self.risk_score += 10

    def _check_typosquatting(self):
        domain = self.extracted.domain
        popular_brands = ['paypal', 'google', 'microsoft', 'apple', 'netflix', 'amazon', 'facebook', 'instagram', 'bankofamerica', 'chase', 'binance', 'coinbase']
        
        for brand in popular_brands:
            if brand in domain and domain != brand:
                self.findings.append({"check": "Typosquatting / Brand Imitation", "status": "Critical", "weight": 40, "detail": f"Domain '{domain}' embeds trusted brand '{brand}' with potential typosquatting variations."})
                self.risk_score += 40
                break
            elif len(domain) == len(brand) and sum(c1 != c2 for c1, c2 in zip(domain, brand)) == 1:
                self.findings.append({"check": "Typosquatting (Character Substitution)", "status": "Critical", "weight": 45, "detail": f"Domain '{domain}' is visually very similar to popular brand '{brand}'."})
                self.risk_score += 45
                break

    def _check_obfuscation_and_keywords(self):
        full_url = self.raw_url.lower()
        
        keywords = ['login', 'verify', 'secure', 'update', 'account', 'banking', 'signin', 'confirm', 'password', 'credential', 'wallet', 'alert']
        matched_keywords = [kw for kw in keywords if kw in full_url]
        if matched_keywords:
            weight = min(len(matched_keywords) * 10, 25)
            self.findings.append({"check": "Suspicious Keywords", "status": "Warning", "weight": weight, "detail": f"URL contains high-risk phishing keywords: {', '.join(matched_keywords)}."})
            self.risk_score += weight

        if '@' in full_url:
            self.findings.append({"check": "Credential Spoofing (@ symbol)", "status": "Critical", "weight": 35, "detail": "URL contains '@' symbol, which can be used to obscure the true destination domain."})
            self.risk_score += 35
            
        if '-' in self.extracted.domain and any(b in self.extracted.domain for b in ['secure', 'login', 'support', 'auth']):
            self.findings.append({"check": "Hyphenated Brand Keywords", "status": "Suspicious", "weight": 20, "detail": "Domain combines hyphens with sensitive service words."})
            self.risk_score += 20

        if len(self.raw_url) > 100:
            self.findings.append({"check": "Excessive URL Length", "status": "Warning", "weight": 10, "detail": f"URL length is {len(self.raw_url)} characters, often used to hide path parameters."})
            self.risk_score += 10

    def _calculate_risk_level(self):
        self.risk_score = max(0, min(100, self.risk_score))
        if self.risk_score >= 75:
            self.risk_level = "Critical"
        elif self.risk_score >= 50:
            self.risk_level = "High"
        elif self.risk_score >= 25:
            self.risk_level = "Medium"
        else:
            self.risk_level = "Low"

    def get_report(self):
        return {
            "raw_url": self.raw_url,
            "normalized_url": self.normalized_url,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "findings": self.findings
        }

