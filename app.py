from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from functools import wraps
import whois
import re
import hashlib
import json
import os
from datetime import datetime, timedelta
import requests
import pickle
import numpy as np
from urllib.parse import urlparse, unquote
import tldextract
import signal
from contextlib import contextmanager
import pandas as pd
from werkzeug.utils import secure_filename
import math
from collections import Counter
import threading
import ipaddress

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(32).hex())

# File upload configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {'csv'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ============ CONFIGURATION ============
CONFIG = {
    'VIRUSTOTAL_API_KEY': os.environ.get('VIRUSTOTAL_API_KEY', ''),
    'GOOGLE_SAFE_BROWSING_API_KEY': os.environ.get('GSB_API_KEY', ''),
    'PHISHTANK_API_URL': 'http://data.phishtank.com/data/online-valid.json',
    'ML_MODEL_PATH': os.path.join(os.path.dirname(os.path.abspath(__file__)), 'phishing_model.pkl'),
    'ADMIN_USERNAME': os.environ.get('ADMIN_USER', 'admin'),
    'ADMIN_PASSWORD_HASH': os.environ.get('ADMIN_PASS_HASH', hashlib.sha256('admin123'.encode()).hexdigest()),
    'MAX_LOGIN_ATTEMPTS': 5,
    'LOGIN_LOCKOUT_MINUTES': 30,
    'SESSION_TIMEOUT_MINUTES': 60,
    'THREAT_INTEL_ENABLED': True,
    'REQUEST_TIMEOUT': 10,
    'DOMAIN_AGE_TIMEOUT': 5
}

# ============ BRAND DATABASE ============
TRUSTED_BRANDS = {
    'financial': ['paypal', 'chase', 'bankofamerica', 'wellsfargo', 'citi', 'citibank', 'amex', 'americanexpress',
                  'visa', 'mastercard', 'discover', 'stripe', 'square', 'venmo', 'zelle', 'westernunion',
                  'bank', 'creditunion', 'savings', 'checking', 'account', 'wallet'],
    'technology': ['google', 'gmail', 'youtube', 'apple', 'icloud', 'microsoft', 'outlook', 'hotmail', 'live',
                   'amazon', 'aws', 'facebook', 'meta', 'instagram', 'whatsapp', 'twitter', 'x', 'linkedin',
                   'github', 'gitlab', 'dropbox', 'slack', 'zoom', 'teams', 'skype', 'adobe', 'oracle'],
    'retail': ['ebay', 'etsy', 'shopify', 'walmart', 'target', 'bestbuy', 'costco', 'nordstrom', 'macys',
               'amazon', 'aliexpress', 'wish', 'wayfair', 'home depot', 'lowes', 'ikea'],
    'social': ['facebook', 'instagram', 'twitter', 'tiktok', 'snapchat', 'reddit', 'linkedin', 'pinterest',
               'tumblr', 'twitch', 'discord', 'telegram', 'signal'],
    'government': ['irs', 'ssa', 'uscis', 'gov', 'treasury', 'fda', 'cdc', 'epa', 'usps', 'state.gov']
}

SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.buzz', '.click', '.work', '.date',
                   '.racing', '.loan', '.download', '.men', '.gdn', '.stream', '.trade', '.win',
                   '.bid', '.country', '.link', '.kim', '.science']

SUSPICIOUS_KEYWORDS = {
    'urgent': ['urgent', 'immediate', 'now', 'today', 'expires', 'limited', 'act now', 'hurry'],
    'security': ['verify', 'confirm', 'validate', 'secure', 'security', 'protection', 'suspicious', 'unusual activity'],
    'account': ['login', 'signin', 'authenticate', 'password', 'credential', 'account', 'update', 'restore', 'recover'],
    'financial': ['payment', 'billing', 'invoice', 'transaction', 'refund', 'prize', 'won', 'winner', 'lottery'],
    'sensitive': ['ssn', 'social security', 'tax id', 'passport', 'dob', 'birthdate', 'mother maiden']
}

# ============ LOGIN ATTEMPT TRACKING ============
login_attempts = {}

def check_login_lockout(ip):
    if ip in login_attempts:
        attempts, last_attempt = login_attempts[ip]
        if attempts >= CONFIG['MAX_LOGIN_ATTEMPTS']:
            lockout_time = last_attempt + timedelta(minutes=CONFIG['LOGIN_LOCKOUT_MINUTES'])
            if datetime.now() < lockout_time:
                remaining = int((lockout_time - datetime.now()).total_seconds() / 60)
                return False, f"Account locked. Try again in {remaining} minutes"
            else:
                login_attempts[ip] = (0, datetime.now())
    return True, ""

def record_login_attempt(ip, success):
    if ip not in login_attempts:
        login_attempts[ip] = (0, datetime.now())
    attempts, _ = login_attempts[ip]
    if success:
        login_attempts[ip] = (0, datetime.now())
    else:
        login_attempts[ip] = (attempts + 1, datetime.now())

# ============ AUTHENTICATION DECORATORS ============
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect(url_for('admin_login'))
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if datetime.now() - last_activity > timedelta(minutes=CONFIG['SESSION_TIMEOUT_MINUTES']):
                session.clear()
                flash('Session expired. Please login again.', 'warning')
                return redirect(url_for('admin_login'))
        session['last_activity'] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return decorated_function

# ============ TIMEOUT HANDLER ============
class TimeoutException(Exception):
    pass

@contextmanager
def time_limit(seconds):
    def signal_handler(signum, frame):
        raise TimeoutException("Timed out")
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)

# ============ LAYER 1: URL PARSER ============
class URLParser:
    def __init__(self, url):
        self.original_url = url
        self.normalized_url = self._normalize_url(url)
        self.parsed = urlparse(self.normalized_url)
        self.extracted = tldextract.extract(self.normalized_url)
        
        self.protocol = self.parsed.scheme
        self.subdomain = self.extracted.subdomain
        self.domain = self.extracted.domain
        self.suffix = self.extracted.suffix
        self.registered_domain = f"{self.domain}.{self.suffix}" if self.suffix else self.domain
        self.full_domain = f"{self.subdomain}.{self.registered_domain}" if self.subdomain else self.registered_domain
        self.path = unquote(self.parsed.path)
        self.path_components = [p for p in self.path.split('/') if p]  # FIXED: Added as instance attribute
        self.query = unquote(self.parsed.query)
        self.fragment = self.parsed.fragment
        self.port = self.parsed.port
        
    def _normalize_url(self, url):
        url = url.strip().lower()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        url = re.sub(r'^https?://www\.', 'https://', url)
        return url
    
    def get_components(self):
        return {
            'original': self.original_url,
            'normalized': self.normalized_url,
            'protocol': self.protocol,
            'subdomain': self.subdomain,
            'domain': self.domain,
            'suffix': self.suffix,
            'registered_domain': self.registered_domain,
            'full_domain': self.full_domain,
            'path': self.path,
            'query': self.query,
            'path_components': self.path_components,  # Now uses the instance attribute
            'query_params': self._parse_query_params()
        }
    
    def _parse_query_params(self):
        params = {}
        if self.query:
            for pair in self.query.split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    params[key] = value
        return params
    
    def is_ip_based(self):
        try:
            ipaddress.ip_address(self.domain)
            return True
        except ValueError:
            return False

# ============ LAYER 2: BRAND IMPERSONATION DETECTOR ============
class BrandImpersonationDetector:
    def __init__(self, url_parser):
        self.parser = url_parser
        self.findings = []
        self.impersonated_brand = None
        self.confidence = 0
        
    def analyze(self):
        self._check_subdomain_impersonation()
        self._check_path_impersonation()
        self._check_typosquatting()
        self._check_combined_attacks()
        return self._get_result()
    
    def _check_subdomain_impersonation(self):
        subdomain = self.parser.subdomain
        
        if not subdomain or subdomain in ['www', 'mail', 'ftp']:
            return
            
        for category, brands in TRUSTED_BRANDS.items():
            for brand in brands:
                if brand in subdomain:
                    if brand not in self.parser.registered_domain:
                        self.findings.append({
                            'severity': 'CRITICAL',
                            'type': 'subdomain_impersonation',
                            'brand': brand,
                            'description': f"{brand.title()} appears in subdomain '{subdomain}' but not in registered domain '{self.parser.registered_domain}'",
                            'evidence': f"subdomain={subdomain}, domain={self.parser.registered_domain}"
                        })
                        self.impersonated_brand = brand
                        self.confidence = max(self.confidence, 0.9)
                        return
    
    def _check_path_impersonation(self):
        path_lower = self.parser.path.lower()
        
        for category, brands in TRUSTED_BRANDS.items():
            for brand in brands:
                if brand in path_lower:
                    if brand not in self.parser.registered_domain:
                        login_indicators = ['login', 'signin', 'auth', 'verify', 'secure']
                        has_login_context = any(ind in path_lower for ind in login_indicators)
                        
                        severity = 'CRITICAL' if has_login_context else 'HIGH'
                        self.findings.append({
                            'severity': severity,
                            'type': 'path_impersonation',
                            'brand': brand,
                            'description': f"{brand.title()} in URL path on unrelated domain",
                            'evidence': f"path={self.parser.path}, domain={self.parser.registered_domain}",
                            'has_login_context': has_login_context
                        })
                        if not self.impersonated_brand:
                            self.impersonated_brand = brand
                        self.confidence = max(self.confidence, 0.85 if has_login_context else 0.7)
    
    def _check_typosquatting(self):
        domain = self.parser.domain
        
        common_substitutions = {
            'paypa1': 'paypal',
            'amaz0n': 'amazon',
            'g00gle': 'google',
            'micr0soft': 'microsoft',
            'faceb00k': 'facebook',
            'app1e': 'apple',
            '1cloud': 'icloud'
        }
        
        for typo, original in common_substitutions.items():
            if typo in domain:
                self.findings.append({
                    'severity': 'HIGH',
                    'type': 'typosquatting',
                    'brand': original,
                    'description': f"Possible typosquatting: '{typo}' mimics '{original}'",
                    'evidence': f"domain={domain}"
                })
                self.impersonated_brand = original
                self.confidence = max(self.confidence, 0.8)
    
    def _check_combined_attacks(self):
        found_brands = []
        all_text = f"{self.parser.subdomain} {self.parser.path}".lower()
        
        for category, brands in TRUSTED_BRANDS.items():
            for brand in brands:
                if brand in all_text or brand in self.parser.domain:
                    found_brands.append(brand)
        
        if len(found_brands) > 1:
            self.findings.append({
                'severity': 'HIGH',
                'type': 'multi_brand_attack',
                'brands': found_brands,
                'description': f"Multiple brands detected: {', '.join(found_brands[:3])}",
                'evidence': "Unusual to have multiple competing brands in one URL"
            })
            self.confidence = max(self.confidence, 0.75)
    
    def _get_result(self):
        return {
            'impersonation_detected': len(self.findings) > 0,
            'impersonated_brand': self.impersonated_brand,
            'findings': self.findings,
            'confidence': self.confidence,
            'severity': self._get_max_severity()
        }
    
    def _get_max_severity(self):
        if not self.findings:
            return 'NONE'
        severities = [f['severity'] for f in self.findings]
        if 'CRITICAL' in severities:
            return 'CRITICAL'
        if 'HIGH' in severities:
            return 'HIGH'
        return 'MEDIUM'

# ============ LAYER 3: STRUCTURAL ANOMALY DETECTOR ============
class StructuralAnomalyDetector:
    def __init__(self, url_parser):
        self.parser = url_parser
        self.anomalies = []
        
    def analyze(self):
        self._check_suspicious_tld()
        self._check_ip_based_url()
        self._check_at_symbol()
        self._check_excessive_dots()
        self._check_url_length()
        self._check_path_depth()
        self._check_encoding_obfuscation()
        self._check_port_anomaly()
        self._check_double_slash_redirect()
        return {
            'anomalies_detected': len(self.anomalies) > 0,
            'anomalies': self.anomalies,
            'anomaly_score': self._calculate_anomaly_score(),
            'suspicious_patterns': [a['type'] for a in self.anomalies]
        }
    
    def _check_suspicious_tld(self):
        suffix = f".{self.parser.suffix}" if self.parser.suffix else ""
        
        for tld in SUSPICIOUS_TLDS:
            if suffix == tld or self.parser.registered_domain.endswith(tld):
                self.anomalies.append({
                    'severity': 'MEDIUM',
                    'type': 'suspicious_tld',
                    'description': f"Domain uses suspicious TLD '{tld}' commonly used for phishing",
                    'evidence': f"suffix={self.parser.suffix}"
                })
                break
    
    def _check_ip_based_url(self):
        if self.parser.is_ip_based():
            self.anomalies.append({
                'severity': 'HIGH',
                'type': 'ip_based_url',
                'description': "URL uses IP address instead of domain name - common in phishing",
                'evidence': f"ip={self.parser.domain}"
            })
    
    def _check_at_symbol(self):
        if '@' in self.parser.normalized_url:
            self.anomalies.append({
                'severity': 'CRITICAL',
                'type': 'at_symbol',
                'description': "URL contains '@' symbol - potential credential harvesting or redirect attack",
                'evidence': "username@hostname pattern detected"
            })
    
    def _check_excessive_dots(self):
        dot_count = self.parser.normalized_url.count('.')
        if dot_count > 4:
            self.anomalies.append({
                'severity': 'MEDIUM',
                'type': 'excessive_dots',
                'description': f"Unusual number of dots ({dot_count}) suggesting subdomain abuse",
                'evidence': f"dot_count={dot_count}"
            })
    
    def _check_url_length(self):
        length = len(self.parser.normalized_url)
        if length > 100:
            severity = 'HIGH' if length > 200 else 'MEDIUM'
            self.anomalies.append({
                'severity': severity,
                'type': 'excessive_length',
                'description': f"URL is unusually long ({length} chars) - possible obfuscation",
                'evidence': f"length={length}"
            })
    
    def _check_path_depth(self):
        depth = len(self.parser.path_components)  # Now works because path_components is an instance attribute
        if depth > 5:
            self.anomalies.append({
                'severity': 'LOW',
                'type': 'deep_path',
                'description': f"Deep directory structure ({depth} levels) - unusual for legitimate sites",
                'evidence': f"path_depth={depth}"
            })
    
    def _check_encoding_obfuscation(self):
        if '%' in self.parser.original_url:
            encoded_chars = len(re.findall(r'%[0-9a-fA-F]{2}', self.parser.original_url))
            if encoded_chars > 5:
                self.anomalies.append({
                    'severity': 'MEDIUM',
                    'type': 'encoding_obfuscation',
                    'description': f"Heavy URL encoding ({encoded_chars} encoded characters) - possible obfuscation",
                    'evidence': "Excessive percent-encoding detected"
                })
    
    def _check_port_anomaly(self):
        if self.parser.port and self.parser.port not in [80, 443]:
            self.anomalies.append({
                'severity': 'MEDIUM',
                'type': 'non_standard_port',
                'description': f"Unusual port number {self.parser.port}",
                'evidence': f"port={self.parser.port}"
            })
    
    def _check_double_slash_redirect(self):
        if '//' in self.parser.path:
            self.anomalies.append({
                'severity': 'MEDIUM',
                'type': 'double_slash_redirect',
                'description': "Double slash in path - possible redirect or protocol confusion attack",
                'evidence': f"path={self.parser.path}"
            })
    
    def _calculate_anomaly_score(self):
        weights = {'CRITICAL': 10, 'HIGH': 5, 'MEDIUM': 3, 'LOW': 1}
        return sum(weights.get(a['severity'], 0) for a in self.anomalies)

# ============ LAYER 4: KEYWORD CONTEXT ANALYZER ============
class KeywordContextAnalyzer:
    def __init__(self, url_parser):
        self.parser = url_parser
        self.findings = []
        
    def analyze(self):
        full_text = f"{self.parser.subdomain} {self.parser.path} {self.parser.query}".lower()
        
        self._check_urgency_context(full_text)
        self._check_security_context(full_text)
        self._check_financial_context(full_text)
        self._check_credential_context(full_text)
        self._check_suspicious_combinations(full_text)
        
        return {
            'keywords_detected': len(self.findings) > 0,
            'findings': self.findings,
            'context_score': self._calculate_context_score(),
            'primary_intent': self._determine_intent()
        }
    
    def _check_urgency_context(self, text):
        found = [k for k in SUSPICIOUS_KEYWORDS['urgent'] if k in text]
        if found:
            self.findings.append({
                'category': 'urgency',
                'keywords': found,
                'severity': 'MEDIUM',
                'description': f"Urgency indicators: {', '.join(found[:3])}",
                'context': "Creates time pressure to bypass security thinking"
            })
    
    def _check_security_context(self, text):
        found = [k for k in SUSPICIOUS_KEYWORDS['security'] if k in text]
        if found:
            security_vendors = ['symantec', 'mcafee', 'norton', 'kaspersky', 'avast']
            is_vendor = any(v in self.parser.registered_domain for v in security_vendors)
            
            if not is_vendor:
                self.findings.append({
                    'category': 'security_urgency',
                    'keywords': found,
                    'severity': 'HIGH',
                    'description': f"Security keywords on non-security site: {', '.join(found[:3])}",
                    'context': "Fake security warnings common in phishing"
                })
    
    def _check_financial_context(self, text):
        found = [k for k in SUSPICIOUS_KEYWORDS['financial'] if k in text]
        if found:
            self.findings.append({
                'category': 'financial',
                'keywords': found,
                'severity': 'MEDIUM',
                'description': f"Financial indicators: {', '.join(found[:3])}",
                'context': "Financial targeting detected"
            })
    
    def _check_credential_context(self, text):
        found = [k for k in SUSPICIOUS_KEYWORDS['account'] if k in text]
        
        login_patterns = ['login', 'signin', 'authenticate', 'password', 'credential']
        has_login = any(p in text for p in login_patterns)
        
        if found and has_login:
            self.findings.append({
                'category': 'credential_harvesting',
                'keywords': found,
                'severity': 'HIGH',
                'description': f"Credential harvesting context: {', '.join(found[:3])}",
                'context': "URL designed to capture login credentials"
            })
    
    def _check_suspicious_combinations(self, text):
        dangerous_combos = [
            (['verify', 'account'], ['security', 'suspended']),
            (['update', 'payment'], ['confirm', 'billing']),
            (['suspended', 'account'], ['restore', 'verify'])
        ]
        
        for combo in dangerous_combos:
            if all(any(k in text for k in group) for group in combo):
                self.findings.append({
                    'category': 'suspicious_combination',
                    'keywords': [k for group in combo for k in group],
                    'severity': 'HIGH',
                    'description': f"Dangerous keyword combination detected",
                    'context': "Classic phishing phrase pattern identified"
                })
                break
    
    def _calculate_context_score(self):
        weights = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        return sum(weights.get(f['severity'], 1) for f in self.findings)
    
    def _determine_intent(self):
        categories = [f['category'] for f in self.findings]
        if 'credential_harvesting' in categories:
            return 'CREDENTIAL_THEFT'
        if 'financial' in categories:
            return 'FINANCIAL_FRAUD'
        if 'security_urgency' in categories:
            return 'FAKE_SECURITY_ALERT'
        if 'urgency' in categories:
            return 'URGENCY_MANIPULATION'
        return 'UNKNOWN'

# ============ LAYER 5: WEIGHTED RISK SCORING ENGINE ============
class RiskScoringEngine:
    WEIGHTS = {
        'brand_subdomain_impersonation': 10,
        'at_symbol': 10,
        'typosquatting': 9,
        'ip_based_url': 8,
        'brand_path_impersonation_login': 7,
        'credential_harvesting_context': 6,
        'suspicious_tld': 4,
        'security_keywords_non_vendor': 4,
        'encoding_obfuscation': 3,
        'excessive_length': 3,
        'non_standard_port': 3,
        'double_slash_redirect': 3,
        'no_https': 2,
        'deep_path': 1,
        'excessive_dots': 1,
        'urgency_keywords': 1,
        'ml_phishing_prediction': 5,
        'virustotal_flagged': 8,
        'google_safe_browsing_flagged': 10,
        'phishtank_known': 10
    }
    
    def __init__(self, url_parser, brand_result, anomaly_result, keyword_result, ml_result=None, threat_result=None):
        self.parser = url_parser
        self.brand = brand_result
        self.anomaly = anomaly_result
        self.keyword = keyword_result
        self.ml = ml_result or {}
        self.threat = threat_result or {}
        
    def calculate(self):
        score = 0
        factors = []
        max_possible = 0
        
        if self.brand['impersonation_detected']:
            for finding in self.brand['findings']:
                if finding['type'] == 'subdomain_impersonation':
                    score += self.WEIGHTS['brand_subdomain_impersonation']
                    factors.append({
                        'layer': 'BRAND',
                        'factor': 'Brand in subdomain (not in domain)',
                        'severity': 'CRITICAL',
                        'weight': self.WEIGHTS['brand_subdomain_impersonation'],
                        'description': finding['description']
                    })
                    max_possible += self.WEIGHTS['brand_subdomain_impersonation']
                elif finding['type'] == 'path_impersonation':
                    weight = self.WEIGHTS['brand_path_impersonation_login'] if finding.get('has_login_context') else 5
                    score += weight
                    factors.append({
                        'layer': 'BRAND',
                        'factor': 'Brand impersonation in path',
                        'severity': finding['severity'],
                        'weight': weight,
                        'description': finding['description']
                    })
                    max_possible += weight
                elif finding['type'] == 'typosquatting':
                    score += self.WEIGHTS['typosquatting']
                    factors.append({
                        'layer': 'BRAND',
                        'factor': 'Typosquatting detected',
                        'severity': 'HIGH',
                        'weight': self.WEIGHTS['typosquatting'],
                        'description': finding['description']
                    })
                    max_possible += self.WEIGHTS['typosquatting']
        
        for anomaly in self.anomaly['anomalies']:
            weight_key = anomaly['type']
            if weight_key in self.WEIGHTS:
                weight = self.WEIGHTS[weight_key]
                score += weight
                factors.append({
                    'layer': 'STRUCTURE',
                    'factor': anomaly['type'].replace('_', ' ').title(),
                    'severity': anomaly['severity'],
                    'weight': weight,
                    'description': anomaly['description']
                })
                max_possible += weight
        
        for finding in self.keyword['findings']:
            if finding['category'] == 'credential_harvesting':
                score += self.WEIGHTS['credential_harvesting_context']
                factors.append({
                    'layer': 'KEYWORD',
                    'factor': 'Credential harvesting intent',
                    'severity': 'HIGH',
                    'weight': self.WEIGHTS['credential_harvesting_context'],
                    'description': finding['description']
                })
                max_possible += self.WEIGHTS['credential_harvesting_context']
            elif finding['severity'] == 'HIGH':
                score += self.WEIGHTS['security_keywords_non_vendor']
                factors.append({
                    'layer': 'KEYWORD',
                    'factor': 'Suspicious security context',
                    'severity': 'HIGH',
                    'weight': self.WEIGHTS['security_keywords_non_vendor'],
                    'description': finding['description']
                })
                max_possible += self.WEIGHTS['security_keywords_non_vendor']
            else:
                score += self.WEIGHTS['urgency_keywords']
                factors.append({
                    'layer': 'KEYWORD',
                    'factor': 'Urgency manipulation',
                    'severity': 'MEDIUM',
                    'weight': self.WEIGHTS['urgency_keywords'],
                    'description': finding['description']
                })
                max_possible += self.WEIGHTS['urgency_keywords']
        
        ml_confidence = self.ml.get('phishing_probability', 0)
        if ml_confidence > 0.7:
            ml_contribution = self.WEIGHTS['ml_phishing_prediction'] * ml_confidence
            score += ml_contribution
            factors.append({
                'layer': 'ML_MODEL',
                'factor': 'ML phishing prediction',
                'severity': 'HIGH' if ml_confidence > 0.8 else 'MEDIUM',
                'weight': round(ml_contribution, 2),
                'description': f"Machine learning model {ml_confidence:.1%} confident of phishing"
            })
            max_possible += self.WEIGHTS['ml_phishing_prediction']
        
        if self.threat.get('virustotal', {}).get('reputation_score', 0) > 3:
            score += self.WEIGHTS['virustotal_flagged']
            factors.append({
                'layer': 'THREAT_INTEL',
                'factor': 'VirusTotal detection',
                'severity': 'HIGH',
                'weight': self.WEIGHTS['virustotal_flagged'],
                'description': f"{self.threat['virustotal']['reputation_score']} security vendors flagged this URL"
            })
            max_possible += self.WEIGHTS['virustotal_flagged']
        
        if self.threat.get('google_safe_browsing', {}).get('threat_found'):
            score += self.WEIGHTS['google_safe_browsing_flagged']
            factors.append({
                'layer': 'THREAT_INTEL',
                'factor': 'Google Safe Browsing block',
                'severity': 'CRITICAL',
                'weight': self.WEIGHTS['google_safe_browsing_flagged'],
                'description': f"Google detected: {self.threat['google_safe_browsing'].get('threat_type', 'Threat')}"
            })
            max_possible += self.WEIGHTS['google_safe_browsing_flagged']
        
        if self.parser.protocol != 'https':
            score += self.WEIGHTS['no_https']
            factors.append({
                'layer': 'SECURITY',
                'factor': 'No HTTPS encryption',
                'severity': 'LOW',
                'weight': self.WEIGHTS['no_https'],
                'description': "Connection not encrypted - credential risk"
            })
            max_possible += self.WEIGHTS['no_https']
        
        normalized_score = min(100, int((score / max(max_possible, 1)) * 100))
        
        return {
            'raw_score': round(score, 2),
            'max_possible': max_possible,
            'normalized_score': normalized_score,
            'risk_level': self._get_risk_level(normalized_score),
            'confidence': self._calculate_confidence(factors),
            'factors': sorted(factors, key=lambda x: x['weight'], reverse=True),
            'primary_threats': [f for f in factors if f['severity'] in ['CRITICAL', 'HIGH']][:3]
        }
    
    def _get_risk_level(self, score):
        if score >= 70:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        elif score >= 15:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def _calculate_confidence(self, factors):
        if not factors:
            return 0.5
        
        layers = len(set(f['layer'] for f in factors))
        layer_bonus = min(0.2, layers * 0.05)
        
        critical_count = sum(1 for f in factors if f['severity'] == 'CRITICAL')
        critical_bonus = min(0.3, critical_count * 0.15)
        
        base_confidence = 0.5 + layer_bonus + critical_bonus
        return min(0.99, base_confidence)

# ============ MAIN DETECTION PIPELINE ============
class PhishingDetectionPipeline:
    def __init__(self, url):
        self.url = url
        self.results = {}
        
    def analyze(self):
        self.parser = URLParser(self.url)
        self.results['url_structure'] = self.parser.get_components()
        
        brand_detector = BrandImpersonationDetector(self.parser)
        self.results['brand_analysis'] = brand_detector.analyze()
        
        anomaly_detector = StructuralAnomalyDetector(self.parser)
        self.results['structural_analysis'] = anomaly_detector.analyze()
        
        keyword_analyzer = KeywordContextAnalyzer(self.parser)
        self.results['keyword_analysis'] = keyword_analyzer.analyze()
        
        self.results['ml_prediction'] = self._get_ml_prediction()
        self.results['threat_intelligence'] = self._get_threat_intel()
        
        scoring_engine = RiskScoringEngine(
            self.parser,
            self.results['brand_analysis'],
            self.results['structural_analysis'],
            self.results['keyword_analysis'],
            self.results['ml_prediction'],
            self.results['threat_intelligence']
        )
        self.results['risk_assessment'] = scoring_engine.calculate()
        
        return self._format_output()
    
    def _get_ml_prediction(self):
        try:
            if ml_model.model:
                return ml_model.predict(self.parser.normalized_url)
        except Exception as e:
            pass
        return {'phishing_probability': 0.5, 'confidence': 0.5}
    
    def _get_threat_intel(self):
        result = {}
        if CONFIG.get('THREAT_INTEL_ENABLED', True):
            try:
                result['virustotal'] = threat_intel.check_virustotal(self.parser.normalized_url)
                result['google_safe_browsing'] = threat_intel.check_google_safe_browsing(self.parser.normalized_url)
                result['phishtank'] = threat_intel.check_phishtank(self.parser.normalized_url)
            except Exception as e:
                result['error'] = str(e)
        return result
    
    def _format_output(self):
        risk = self.results['risk_assessment']
        
        verdict = self._generate_verdict(risk)
        recommendations = self._generate_recommendations(risk)
        
        return {
            'url': self.url,
            'normalized_url': self.parser.normalized_url,
            'domain_info': {
                'subdomain': self.parser.subdomain,
                'domain': self.parser.domain,
                'suffix': self.parser.suffix,
                'registered_domain': self.parser.registered_domain
            },
            'verdict': verdict,
            'risk_level': risk['risk_level'],
            'risk_score': risk['normalized_score'],
            'confidence': round(risk['confidence'] * 100, 1),
            'primary_threats': risk['primary_threats'],
            'all_factors': risk['factors'],
            'layered_results': {
                'brand_impersonation': self.results['brand_analysis'],
                'structural_anomalies': self.results['structural_analysis'],
                'keyword_context': self.results['keyword_analysis'],
                'ml_prediction': self.results['ml_prediction'],
                'threat_intelligence': self.results['threat_intelligence']
            },
            'recommendations': recommendations,
            'timestamp': datetime.now().isoformat()
        }
    
    def _generate_verdict(self, risk):
        level = risk['risk_level']
        factors = risk['factors']
        
        if level == 'HIGH':
            if any(f['layer'] == 'BRAND' for f in risk['primary_threats']):
                return "PHISHING DETECTED: This URL appears to be impersonating a trusted brand. Do not enter credentials."
            elif any(f['layer'] == 'THREAT_INTEL' for f in risk['primary_threats']):
                return "CONFIRMED MALICIOUS: This URL is flagged by security vendors as dangerous."
            else:
                return "HIGH RISK: Multiple suspicious indicators detected. Avoid this URL."
        
        elif level == 'MEDIUM':
            brand_issues = [f for f in factors if f['layer'] == 'BRAND']
            if brand_issues:
                return "SUSPICIOUS: Possible brand impersonation or misleading structure detected."
            else:
                return "SUSPICIOUS: Several unusual patterns detected. Proceed with caution."
        
        elif level == 'LOW':
            return "LOW RISK: Minor anomalies detected, but no clear malicious indicators."
        
        else:
            return "SAFE: No significant threats detected by automated analysis."
    
    def _generate_recommendations(self, risk):
        recs = []
        level = risk['risk_level']
        
        if level == 'HIGH':
            recs.append("BLOCK: Do not visit this URL")
            recs.append("Do not enter any credentials or personal information")
            recs.append("Report to security team immediately")
            for f in risk['primary_threats']:
                if f.get('brand'):
                    recs.append(f"Verify directly with {f['brand']} through official channels")
        
        elif level == 'MEDIUM':
            recs.append("CAUTION: Verify URL carefully before proceeding")
            recs.append("Check for HTTPS padlock icon")
            recs.append("Do not enter credentials unless certain of legitimacy")
            recs.append("Consider visiting site directly by typing known domain")
        
        elif level == 'LOW':
            recs.append("Standard precautions recommended")
            recs.append("Verify site appears legitimate")
        
        else:
            recs.append("No special action required")
            recs.append("Standard browsing security practices apply")
        
        return recs

# ============ BACKWARD COMPATIBILITY ============
def analyze_url_production(url):
    try:
        pipeline = PhishingDetectionPipeline(url)
        result = pipeline.analyze()
        
        return {
            "result": result['risk_level'] if result['risk_level'] != 'MINIMAL' else 'Safe',
            "score": result['risk_score'],
            "confidence": result['confidence'] / 100,
            "risk_level": result['risk_level'],
            "verdict": result['verdict'],
            "reasons": [t['description'] for t in result['primary_threats']] if result['primary_threats'] else ["No significant threats detected"],
            "recommendations": result['recommendations'],
            "ml_features": result['layered_results']['ml_prediction'].get('features', {}),
            "threat_intelligence": result['layered_results']['threat_intelligence'],
            "domain_info": result['domain_info'],
            "all_factors": result['all_factors']
        }
    except Exception as e:
        return {
            "result": "Error",
            "score": 0,
            "confidence": 0,
            "risk_level": "UNKNOWN",
            "verdict": f"Analysis failed: {str(e)}",
            "reasons": ["System error during analysis"],
            "recommendations": ["Retry analysis or contact administrator"],
            "ml_features": {},
            "threat_intelligence": {}
        }

# ============ FEATURE EXTRACTION FOR TRAINING ============
def extract_features_from_url(url):
    features = {}
    try:
        parsed = urlparse(url)
        extracted = tldextract.extract(url)

        features['url_length'] = len(url)
        features['has_https'] = 1 if parsed.scheme == 'https' else 0
        features['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
        features['path_length'] = len(parsed.path)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['has_at_symbol'] = 1 if '@' in url else 0
        features['has_ip_address'] = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', extracted.domain) else 0

        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.buzz', '.click', '.work', '.date', '.racing', '.loan', '.download', '.men', '.gdn']
        features['suspicious_tld'] = 1 if any(url.endswith(tld) for tld in suspicious_tlds) else 0

        keywords = ['login', 'verify', 'secure', 'account', 'password', 'bank', 'update', 'confirm', 'security', 'authentication', 'wallet', 'crypto', 'bitcoin']
        features['has_suspicious_keywords'] = sum(1 for kw in keywords if kw in url.lower())

        if len(url) > 0:
            prob = [float(url.count(c)) / len(url) for c in dict.fromkeys(list(url))]
            features['entropy_score'] = -sum(p * math.log(p) / math.log(2) for p in prob if p > 0)
        else:
            features['entropy_score'] = 0

        brands = ['paypal', 'google', 'amazon', 'apple', 'microsoft', 'facebook', 'netflix', 'bank', 'chase', 'wellsfargo', 'citi', 'amex', 'visa', 'mastercard']
        subdomain = extracted.subdomain.lower()
        features['brand_in_subdomain'] = sum(1 for brand in brands if brand in subdomain)

        features['domain_age_days'] = -1

    except Exception as e:
        for name in ['url_length', 'has_https', 'domain_age_days', 'has_at_symbol',
                     'subdomain_count', 'path_length', 'num_dots', 'num_hyphens',
                     'has_ip_address', 'suspicious_tld', 'brand_in_subdomain',
                     'has_suspicious_keywords', 'entropy_score']:
            features[name] = 0
    
    return features

# ============ MODEL TRAINER ============
class ModelTrainer:
    def __init__(self):
        self.feature_names = [
            'url_length', 'has_https', 'domain_age_days', 'has_at_symbol',
            'subdomain_count', 'path_length', 'num_dots', 'num_hyphens',
            'has_ip_address', 'suspicious_tld', 'brand_in_subdomain',
            'has_suspicious_keywords', 'entropy_score'
        ]
        self.training_status = {
            'is_training': False,
            'progress': 0,
            'message': '',
            'last_result': None
        }

    def validate_csv(self, filepath):
        try:
            df = pd.read_csv(filepath)
            required_columns = ['url', 'label']
            
            missing = [col for col in required_columns if col not in df.columns]
            if missing:
                return False, f"Missing columns: {', '.join(missing)}"
            
            if df.empty:
                return False, "CSV file is empty"
            
            if not df['label'].isin([0, 1]).all():
                return False, "Label column must contain only 0 (legitimate) or 1 (phishing)"
            
            return True, f"Valid CSV with {len(df)} rows"
        except Exception as e:
            return False, f"Error reading CSV: {str(e)}"

    def prepare_data_from_csv(self, filepath):
        df = pd.read_csv(filepath)
        data = []
        
        total = len(df)
        for idx, row in df.iterrows():
            features = extract_features_from_url(str(row['url']))
            features['label'] = int(row['label'])
            data.append(features)
            
            self.training_status['progress'] = int((idx + 1) / total * 30)
            self.training_status['message'] = f"Extracting features... {idx + 1}/{total}"
        
        return pd.DataFrame(data)

    def train_from_csv(self, filepath, test_size=0.2):
        self.training_status['is_training'] = True
        self.training_status['progress'] = 0
        self.training_status['message'] = "Starting training..."
        
        try:
            is_valid, msg = self.validate_csv(filepath)
            if not is_valid:
                self.training_status['is_training'] = False
                self.training_status['message'] = msg
                return {'success': False, 'error': msg}

            self.training_status['message'] = "Loading CSV file..."
            df = self.prepare_data_from_csv(filepath)
            
            legit_count = len(df[df['label'] == 0])
            phishing_count = len(df[df['label'] == 1])
            
            if legit_count < 10 or phishing_count < 10:
                self.training_status['is_training'] = False
                return {'success': False, 'error': f"Need at least 10 samples per class. Got {legit_count} legitimate, {phishing_count} phishing"}

            X = df[self.feature_names]
            y = df['label']
            
            self.training_status['progress'] = 40
            self.training_status['message'] = "Splitting dataset..."
            
            from sklearn.model_selection import train_test_split
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=42, stratify=y
            )
            
            self.training_status['progress'] = 50
            self.training_status['message'] = "Training Random Forest model..."
            
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
            
            model = RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1
            )
            
            model.fit(X_train, y_train)
            
            self.training_status['progress'] = 80
            self.training_status['message'] = "Evaluating model..."
            
            y_pred = model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            importance = dict(zip(self.feature_names, model.feature_importances_.tolist()))
            importance = dict(sorted(importance.items(), key=lambda x: x[1], reverse=True))
            
            model_data = {
                'model': model,
                'feature_names': self.feature_names,
                'training_date': datetime.now().isoformat(),
                'samples': len(df),
                'accuracy': accuracy,
                'class_distribution': {'legitimate': legit_count, 'phishing': phishing_count},
                'feature_importance': importance
            }
            
            with open(CONFIG['ML_MODEL_PATH'], 'wb') as f:
                pickle.dump(model_data, f)
            
            self.training_status['progress'] = 100
            self.training_status['message'] = "Training complete!"
            self.training_status['is_training'] = False
            
            result = {
                'success': True,
                'accuracy': round(accuracy, 4),
                'samples': len(df),
                'legitimate': legit_count,
                'phishing': phishing_count,
                'test_samples': len(X_test),
                'feature_importance': importance,
                'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
                'classification_report': classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing'], output_dict=True)
            }
            
            self.training_status['last_result'] = result
            return result
            
        except Exception as e:
            self.training_status['is_training'] = False
            self.training_status['message'] = f"Error: {str(e)}"
            return {'success': False, 'error': str(e)}

    def get_status(self):
        return self.training_status

    def reset_status(self):
        self.training_status = {
            'is_training': False,
            'progress': 0,
            'message': '',
            'last_result': None
        }

model_trainer = ModelTrainer()

# ============ ML MODEL ============
class PhishingMLModel:
    def __init__(self):
        self.model = None
        self.feature_names = [
            'url_length', 'has_https', 'domain_age_days', 'has_at_symbol',
            'subdomain_count', 'path_length', 'num_dots', 'num_hyphens',
            'has_ip_address', 'suspicious_tld', 'brand_in_subdomain',
            'has_suspicious_keywords', 'entropy_score'
        ]
        self.model_info = None
        self.load_model()

    def load_model(self):
        try:
            if os.path.exists(CONFIG['ML_MODEL_PATH']):
                with open(CONFIG['ML_MODEL_PATH'], 'rb') as f:
                    model_data = pickle.load(f)
                    self.model = model_data['model']
                    self.feature_names = model_data.get('feature_names', self.feature_names)
                    self.model_info = {
                        'training_date': model_data.get('training_date', 'Unknown'),
                        'samples': model_data.get('samples', 'Unknown'),
                        'accuracy': model_data.get('accuracy', 'Unknown')
                    }
                print(f"Loaded trained model from {CONFIG['ML_MODEL_PATH']}")
            else:
                print("No trained model found. Please train a model in the admin panel.")
                self._create_dummy_model()
        except Exception as e:
            print(f"Error loading model: {e}")
            self._create_dummy_model()

    def _create_dummy_model(self):
        from sklearn.ensemble import RandomForestClassifier
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        X = np.random.rand(100, len(self.feature_names))
        y = np.random.randint(0, 2, 100)
        self.model.fit(X, y)
        self.model_info = {'training_date': 'Dummy', 'samples': 100, 'accuracy': 0.5}

    def extract_features(self, url):
        features = {}
        try:
            parsed = urlparse(url)
            extracted = tldextract.extract(url)

            features['url_length'] = len(url)
            features['has_https'] = 1 if parsed.scheme == 'https' else 0
            features['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
            features['path_length'] = len(parsed.path)
            features['num_dots'] = url.count('.')
            features['num_hyphens'] = url.count('-')
            features['has_at_symbol'] = 1 if '@' in url else 0
            features['has_ip_address'] = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', extracted.domain) else 0

            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.buzz', '.click', '.work', '.date', '.racing', '.loan', '.download', '.men', '.gdn']
            features['suspicious_tld'] = 1 if any(url.endswith(tld) for tld in suspicious_tlds) else 0

            keywords = ['login', 'verify', 'secure', 'account', 'password', 'bank', 'update', 'confirm', 'security', 'authentication', 'wallet', 'crypto', 'bitcoin']
            features['has_suspicious_keywords'] = sum(1 for kw in keywords if kw in url.lower())

            if len(url) > 0:
                prob = [float(url.count(c)) / len(url) for c in dict.fromkeys(list(url))]
                features['entropy_score'] = -sum(p * math.log(p) / math.log(2) for p in prob if p > 0)
            else:
                features['entropy_score'] = 0

            brands = ['paypal', 'google', 'amazon', 'apple', 'microsoft', 'facebook', 'netflix', 'bank', 'chase', 'wellsfargo', 'citi', 'amex', 'visa', 'mastercard']
            subdomain = extracted.subdomain.lower()
            features['brand_in_subdomain'] = sum(1 for brand in brands if brand in subdomain)

            try:
                domain = f"{extracted.domain}.{extracted.suffix}"
                with time_limit(CONFIG['DOMAIN_AGE_TIMEOUT']):
                    w = whois.whois(domain)
                    if w.creation_date:
                        creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                        if isinstance(creation, datetime):
                            features['domain_age_days'] = (datetime.now() - creation).days
                        else:
                            features['domain_age_days'] = -1
                    else:
                        features['domain_age_days'] = -1
            except:
                features['domain_age_days'] = -1

        except Exception as e:
            for name in self.feature_names:
                features[name] = 0
        
        return [features.get(name, 0) for name in self.feature_names]

    def predict(self, url):
        try:
            features = self.extract_features(url)
            X = np.array(features).reshape(1, -1)
            prediction = self.model.predict(X)[0]
            probability = self.model.predict_proba(X)[0]
            return {
                'is_phishing': bool(prediction),
                'confidence': float(max(probability)),
                'phishing_probability': float(probability[1]),
                'features': dict(zip(self.feature_names, features))
            }
        except Exception as e:
            return {
                'is_phishing': False,
                'confidence': 0.5,
                'phishing_probability': 0.5,
                'features': dict(zip(self.feature_names, features if 'features' in locals() else [0]*len(self.feature_names)))
            }

ml_model = PhishingMLModel()

@app.route('/admin/api/clear-history', methods=['POST'])
@login_required
def clear_scan_history():
    try:
        # Clear all scans from database
        db.data['scans'] = []
        db.save()
        flash('Scan history cleared successfully!', 'success')
        return jsonify({'success': True, 'message': 'History cleared'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============ THREAT INTELLIGENCE ============
class ThreatIntelligence:
    def __init__(self):
        self.phishtank_cache = []
        self.virustotal_cache = {}
        self.last_update = None
        self.cache_duration = timedelta(hours=1)

    def check_phishtank(self, url):
        try:
            return {'found': False, 'note': 'PhishTank check disabled in demo'}
        except Exception as e:
            return {'found': False, 'error': str(e)}

    def check_virustotal(self, url):
        if not CONFIG['VIRUSTOTAL_API_KEY']:
            return {'checked': False, 'reason': 'No API key configured'}
        try:
            headers = {'x-apikey': CONFIG['VIRUSTOTAL_API_KEY']}
            url_id = hashlib.sha256(url.encode()).hexdigest()
            if url_id in self.virustotal_cache:
                cache_time, result = self.virustotal_cache[url_id]
                if datetime.now() - cache_time < self.cache_duration:
                    return result
            vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            response = requests.get(vt_url, headers=headers, timeout=CONFIG['REQUEST_TIMEOUT'])
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                result = {
                    'checked': True,
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'reputation_score': stats.get('malicious', 0) + stats.get('suspicious', 0)
                }
                self.virustotal_cache[url_id] = (datetime.now(), result)
                return result
            else:
                return {'checked': False, 'status_code': response.status_code}
        except Exception as e:
            return {'checked': False, 'error': str(e)}

    def check_google_safe_browsing(self, url):
        if not CONFIG['GOOGLE_SAFE_BROWSING_API_KEY']:
            return {'checked': False, 'reason': 'No API key configured'}
        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={CONFIG['GOOGLE_SAFE_BROWSING_API_KEY']}"
            payload = {
                "client": {"clientId": "phishguard", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            response = requests.post(api_url, json=payload, timeout=CONFIG['REQUEST_TIMEOUT'])
            data = response.json()
            if 'matches' in data:
                return {'checked': True, 'threat_found': True, 'threat_type': data['matches'][0]['threatType'], 'platform': data['matches'][0]['platformType']}
            return {'checked': True, 'threat_found': False}
        except Exception as e:
            return {'checked': False, 'error': str(e)}

threat_intel = ThreatIntelligence()

# ============ DATABASE ============
class Database:
    def __init__(self, db_file=None):
        if db_file is None:
            db_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'phishguard_db.json')
        self.db_file = db_file
        self.data = self.load()

    def load(self):
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                return self._default_data()
        return self._default_data()

    def _default_data(self):
        return {
            'scans': [],
            'users': [],
            'settings': {
                'ml_enabled': True,
                'threat_intel_enabled': True,
                'auto_update': True,
                'notification_email': ''
            },
            'blacklist': [],
            'whitelist': []
        }

    def save(self):
        try:
            with open(self.db_file, 'w') as f:
                json.dump(self.data, f, indent=2, default=str)
        except Exception as e:
            print(f"Error saving database: {e}")

    def add_scan(self, scan_data):
        scan_data['timestamp'] = datetime.now().isoformat()
        scan_data['id'] = hashlib.sha256(f"{scan_data['input']}{datetime.now()}".encode()).hexdigest()[:16]
        self.data['scans'].insert(0, scan_data)
        self.data['scans'] = self.data['scans'][:1000]
        self.save()
        return scan_data['id']

    def get_stats(self):
        scans = self.data['scans']
        total = len(scans)
        if total == 0:
            return {'total': 0, 'safe': 0, 'suspicious': 0, 'malicious': 0, 'safe_pct': 0, 'suspicious_pct': 0, 'malicious_pct': 0}
        safe = sum(1 for s in scans if s.get('result') == 'Safe')
        suspicious = sum(1 for s in scans if s.get('result') == 'Suspicious')
        malicious = sum(1 for s in scans if s.get('result') == 'Malicious')
        return {
            'total': total, 'safe': safe, 'suspicious': suspicious, 'malicious': malicious,
            'safe_pct': round(safe/total*100, 1), 'suspicious_pct': round(suspicious/total*100, 1), 'malicious_pct': round(malicious/total*100, 1)
        }

    def get_recent_scans(self, limit=50):
        return self.data['scans'][:limit]

db = Database()

# ============ ROUTES ============
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    ip = request.remote_addr
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        allowed, message = check_login_lockout(ip)
        if not allowed:
            flash(message, 'danger')
            return render_template('login.html')
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if username == CONFIG['ADMIN_USERNAME'] and password_hash == CONFIG['ADMIN_PASSWORD_HASH']:
            session['admin_logged_in'] = True
            session['last_activity'] = datetime.now().isoformat()
            record_login_attempt(ip, True)
            flash('Login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            record_login_attempt(ip, False)
            remaining = CONFIG['MAX_LOGIN_ATTEMPTS'] - login_attempts[ip][0]
            flash(f"Invalid credentials. {remaining} attempts remaining.", 'danger')
            return render_template('login.html')
    return render_template('login.html')

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('admin_login'))

@app.route('/admin')
@login_required
def admin_dashboard():
    stats = db.get_stats()
    recent_scans = db.get_recent_scans(10)
    settings = db.data['settings']
    model_info = ml_model.model_info if ml_model.model_info else {'training_date': 'Not trained', 'samples': 0, 'accuracy': 0}
    return render_template('admin.html', stats=stats, recent_scans=recent_scans, settings=settings, model_info=model_info)

@app.route('/admin/api/stats')
@login_required
def api_stats():
    return jsonify(db.get_stats())

@app.route('/admin/api/scans')
@login_required
def api_scans():
    limit = request.args.get('limit', 100, type=int)
    return jsonify(db.get_recent_scans(limit))

@app.route('/admin/settings', methods=['POST'])
@login_required
def admin_settings():
    db.data['settings']['ml_enabled'] = request.form.get('ml_enabled') == 'on'
    db.data['settings']['threat_intel_enabled'] = request.form.get('threat_intel_enabled') == 'on'
    db.data['settings']['auto_update'] = request.form.get('auto_update') == 'on'
    db.data['settings']['notification_email'] = request.form.get('notification_email', '').strip()
    db.save()
    flash('Settings saved successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/model')
@login_required
def model_training_page():
    model_info = ml_model.model_info if ml_model.model_info else {'training_date': 'Not trained', 'samples': 0, 'accuracy': 0}
    training_status = model_trainer.get_status()
    return render_template('model_training.html', model_info=model_info, training_status=training_status)

@app.route('/admin/api/model/status')
@login_required
def model_status():
    model_info = ml_model.model_info if ml_model.model_info else {'training_date': 'Not trained', 'samples': 0, 'accuracy': 0}
    training_status = model_trainer.get_status()
    return jsonify({'model_info': model_info, 'training_status': training_status})

@app.route('/admin/api/model/upload', methods=['POST'])
@login_required
def upload_training_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    if not file.filename.endswith('.csv'):
        return jsonify({'success': False, 'error': 'Only CSV files allowed'}), 400
    filename = secure_filename(f"training_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    is_valid, msg = model_trainer.validate_csv(filepath)
    if not is_valid:
        os.remove(filepath)
        return jsonify({'success': False, 'error': msg}), 400
    def train_async():
        result = model_trainer.train_from_csv(filepath)
        ml_model.load_model()
    thread = threading.Thread(target=train_async)
    thread.start()
    return jsonify({'success': True, 'message': 'Training started', 'filename': filename})

@app.route('/admin/api/model/progress')
@login_required
def training_progress():
    return jsonify(model_trainer.get_status())

@app.route('/admin/api/model/reset', methods=['POST'])
@login_required
def reset_training_status():
    model_trainer.reset_status()
    return jsonify({'success': True})

@app.route('/admin/api/model/download-template')
@login_required
def download_template():
    import csv
    import io
    from flask import send_file
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['url', 'label'])
    writer.writerow(['https://www.google.com', '0'])
    writer.writerow(['https://www.amazon.com', '0'])
    writer.writerow(['http://paypa1.com/login', '1'])
    writer.writerow(['https://google-verify.tk/login', '1'])
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name='training_template.csv'
    )

@app.route('/scan_url', methods=['POST'])
def scan_url():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON data"}), 400
        url = data.get('url', '').strip()
        if not url:
            return jsonify({"error": "No URL provided"}), 400
        
        result = analyze_url_production(url)
        
        if result['result'] != 'Error':
            scan_record = {
                'type': 'url',
                'input': url,
                'result': result['risk_level'],
                'score': result['score'],
                'confidence': result.get('confidence', 0),
                'verdict': result.get('verdict', ''),
                'reasons': result.get('reasons', [])
            }
            db.add_scan(scan_record)
        
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)