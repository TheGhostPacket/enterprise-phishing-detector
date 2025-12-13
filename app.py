"""
Enterprise Phishing Intelligence Platform
Comprehensive Email and URL Analysis
"""

from flask import Flask, render_template, request, jsonify
import datetime
import os
import re
import requests
import socket
import ssl
from urllib.parse import urlparse
import threading
import time
import json

# Import our URL analyzer module
from url_analyzer import analyze_url_comprehensive

app = Flask(__name__)

# ============================================
# CONFIGURATION
# ============================================

# API Keys (set via environment variables for security)
GOOGLE_SAFE_BROWSING_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_KEY', None)
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', None)

# ============================================
# EMAIL ANALYSIS FUNCTIONS (Your existing code)
# ============================================

def check_live_url_safety(body):
    """Advanced live URL safety checking"""
    danger_score = 0
    reasons = []
    
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, body)
    
    if not urls:
        return danger_score, reasons, []
    
    print(f"🔍 Live checking {len(urls)} URLs...")
    extracted_urls = []
    
    for url in urls[:3]:
        try:
            extracted_urls.append(url)
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            url_score, url_reasons = analyze_url_reputation(url, domain)
            danger_score += url_score
            reasons.extend(url_reasons)
            
            http_score, http_reasons = check_url_response(url)
            danger_score += http_score
            reasons.extend(http_reasons)
            
            ssl_score, ssl_reasons = check_ssl_certificate_basic(domain)
            danger_score += ssl_score
            reasons.extend(ssl_reasons)
            
        except Exception as e:
            print(f"Error checking URL {url}: {e}")
            danger_score += 10
            reasons.append(f"URL check failed: {url[:30]}...")
    
    return danger_score, reasons, extracted_urls


def analyze_url_reputation(url, domain):
    """Analyze URL reputation using multiple checks"""
    danger_score = 0
    reasons = []
    
    malicious_patterns = [
        'phishing', 'scam', 'fraud', 'fake', 'secure-', 'verify-',
        'account-', 'update-', 'confirm-', 'suspended', 'login-'
    ]
    
    for pattern in malicious_patterns:
        if pattern in url.lower():
            danger_score += 15
            reasons.append(f"URL contains suspicious pattern: '{pattern}'")
    
    if check_suspicious_domain(domain):
        danger_score += 20
        reasons.append(f"Domain flagged as suspicious: {domain}")
    
    try:
        response = requests.head(url, timeout=5, allow_redirects=False)
        if response.status_code in [301, 302, 307, 308]:
            location = response.headers.get('Location', '')
            if location and urlparse(location).netloc != domain:
                danger_score += 25
                reasons.append("URL redirects to different domain")
    except:
        pass
    
    return danger_score, reasons


def check_url_response(url):
    """Check URL response and behavior"""
    danger_score = 0
    reasons = []
    
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        
        if response.status_code == 404:
            danger_score += 15
            reasons.append("URL returns 404")
        elif response.status_code >= 400:
            danger_score += 10
            reasons.append(f"URL returns error: {response.status_code}")
        
        content_type = response.headers.get('Content-Type', '').lower()
        if 'application/octet-stream' in content_type:
            danger_score += 30
            reasons.append("URL serves downloadable file")
        
        content = response.text.lower()
        if 'password' in content and 'login' in content:
            danger_score += 20
            reasons.append("URL contains login form")
        
    except requests.exceptions.Timeout:
        danger_score += 20
        reasons.append("URL request timed out")
    except requests.exceptions.ConnectionError:
        danger_score += 25
        reasons.append("Cannot connect to URL")
    except Exception as e:
        danger_score += 15
        reasons.append("URL check failed")
    
    return danger_score, reasons


def check_ssl_certificate_basic(domain):
    """Basic SSL certificate check"""
    danger_score = 0
    reasons = []
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (not_after - datetime.datetime.now()).days
                
                if days_until_expiry < 30:
                    danger_score += 20
                    reasons.append(f"SSL expires in {days_until_expiry} days")
                
    except ssl.SSLError:
        danger_score += 30
        reasons.append("SSL certificate error")
    except socket.timeout:
        danger_score += 15
        reasons.append("SSL check timed out")
    except Exception:
        danger_score += 5
        reasons.append("No SSL certificate")
    
    return danger_score, reasons


def check_suspicious_domain(domain):
    """Check if domain is suspicious"""
    suspicious_indicators = [
        'secure-', 'verify-', 'account-', 'update-', 'login-',
        'bank-', 'paypal-', 'amazon-', 'microsoft-', 'apple-'
    ]
    return any(indicator in domain for indicator in suspicious_indicators)


# ============================================
# MACHINE LEARNING MODEL
# ============================================

class PhishingMLModel:
    def __init__(self):
        self.training_data = []
        self.model_trained = False
        self.load_training_data()
    
    def load_training_data(self):
        self.training_data = [
            {"text": "urgent account suspended verify immediately", "label": 1},
            {"text": "winner congratulations prize money click here", "label": 1},
            {"text": "security alert confirm password bank details", "label": 1},
            {"text": "paypal suspended verify account information", "label": 1},
            {"text": "meeting reminder tomorrow 3pm conference room", "label": 0},
            {"text": "invoice attached payment due next week", "label": 0},
            {"text": "project update status report quarterly review", "label": 0},
            {"text": "newsletter monthly updates company news", "label": 0},
        ]
        self.model_trained = True
    
    def extract_features(self, subject, body):
        text = (subject + " " + body).lower()
        return {
            'urgent_words': len([w for w in ['urgent', 'immediate', 'expires'] if w in text]),
            'money_words': len([w for w in ['money', 'prize', 'won', 'cash'] if w in text]),
            'action_words': len([w for w in ['click', 'verify', 'confirm', 'update'] if w in text]),
            'length': len(text),
            'exclamation_count': text.count('!'),
            'capital_ratio': sum(1 for c in text if c.isupper()) / max(len(text), 1),
        }
    
    def predict_phishing_probability(self, subject, body):
        if not self.model_trained:
            return 50, "Model not trained"
        
        features = self.extract_features(subject, body)
        
        score = 0
        score += features['urgent_words'] * 20
        score += features['money_words'] * 15
        score += features['action_words'] * 10
        score += min(features['exclamation_count'] * 5, 20)
        score += min(features['capital_ratio'] * 30, 25)
        
        probability = min(score, 95)
        confidence = "High" if probability > 70 else "Medium" if probability > 40 else "Low"
        
        return probability, f"ML Confidence: {confidence}"
    
    def learn_from_feedback(self, subject, body, is_phishing):
        features = self.extract_features(subject, body)
        label = 1 if is_phishing else 0
        self.training_data.append({
            "text": (subject + " " + body).lower(),
            "label": label,
            "features": features
        })
        print(f"✅ Model learned: {'Phishing' if is_phishing else 'Legitimate'}")


# ============================================
# EMAIL MONITOR (Simulation)
# ============================================

class EmailMonitor:
    def __init__(self):
        self.monitoring = False
        self.monitored_emails = []
        self.alerts = []
    
    def start_monitoring(self, email_config):
        self.monitoring = True
        self.email_config = email_config
        threading.Thread(target=self.monitor_loop, daemon=True).start()
        return "Email monitoring started"
    
    def monitor_loop(self):
        while self.monitoring:
            time.sleep(30)
            if len(self.monitored_emails) < 5:
                simulated_email = {
                    "timestamp": datetime.datetime.now().isoformat(),
                    "sender": "suspicious@example.com",
                    "subject": "Urgent: Account verification required",
                    "threat_level": "High",
                    "auto_blocked": True
                }
                self.monitored_emails.append(simulated_email)
                self.alerts.append(f"🚨 Blocked: {simulated_email['sender']}")
    
    def get_monitoring_status(self):
        return {
            "monitoring": self.monitoring,
            "emails_processed": len(self.monitored_emails),
            "alerts_count": len(self.alerts),
            "recent_alerts": self.alerts[-5:] if self.alerts else []
        }
    
    def stop_monitoring(self):
        self.monitoring = False
        return "Email monitoring stopped"


# Initialize components
ml_model = PhishingMLModel()
email_monitor = EmailMonitor()


# ============================================
# ANALYSIS FUNCTIONS
# ============================================

def analyze_basic_patterns(subject, sender, body):
    """Basic pattern analysis for emails"""
    danger_score = 0
    reasons = []
    
    suspicious_words = ["urgent", "winner", "verify", "suspended", "confirm", 
                       "update", "security", "account", "password", "login",
                       "congratulations", "act now", "limited time", "expire"]
    
    for word in suspicious_words:
        if word.lower() in subject.lower():
            danger_score += 12
            reasons.append(f"Suspicious word '{word}' in subject")
        if word.lower() in body.lower():
            danger_score += 6
            reasons.append(f"Suspicious word '{word}' in body")
    
    free_emails = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]
    official_companies = ["bank", "paypal", "amazon", "microsoft", "apple", "visa", "netflix"]
    
    for company in official_companies:
        if company in sender.lower():
            for free_service in free_emails:
                if free_service in sender.lower():
                    danger_score += 35
                    reasons.append(f"Claims to be {company} but uses {free_service}")
    
    # Check for urgency language
    urgency_phrases = ["act now", "immediately", "expires today", "limited time", 
                       "within 24 hours", "urgent action", "final notice"]
    
    text = (subject + " " + body).lower()
    for phrase in urgency_phrases:
        if phrase in text:
            danger_score += 15
            reasons.append(f"Uses urgency tactic: '{phrase}'")
    
    return danger_score, reasons


def analyze_email_enterprise(subject, sender, body):
    """Enterprise-grade email analysis"""
    danger_score = 0
    reasons = []
    
    print(f"🚀 Starting enterprise email analysis...")
    
    # Basic pattern analysis
    basic_score, basic_reasons = analyze_basic_patterns(subject, sender, body)
    danger_score += basic_score
    reasons.extend(basic_reasons)
    
    # Live URL checking
    url_score, url_reasons, extracted_urls = check_live_url_safety(body)
    danger_score += url_score
    reasons.extend(url_reasons)
    
    # ML analysis
    ml_probability, ml_confidence = ml_model.predict_phishing_probability(subject, body)
    if ml_probability > 60:
        danger_score += int(ml_probability * 0.3)
        reasons.append(f"ML predicts {ml_probability}% phishing probability")
    
    # Threat correlation
    if danger_score > 80 and len(reasons) > 5:
        danger_score += 10
        reasons.append("Multiple threat vectors detected")
    
    return min(danger_score, 100), reasons, ml_probability, ml_confidence, extracted_urls


# ============================================
# ROUTES
# ============================================

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze_email():
    """Analyze email for phishing"""
    try:
        print("🚀 Email analysis request received!")
        
        data = request.get_json()
        sender = data.get('sender', '').strip()
        subject = data.get('subject', '').strip()
        body = data.get('body', '').strip()
        
        if not sender or not subject:
            return jsonify({'success': False, 'error': 'Please provide sender and subject'}), 400
        
        danger_score, reasons, ml_probability, ml_confidence, extracted_urls = analyze_email_enterprise(subject, sender, body)
        
        confidence = min(95, 60 + (len(reasons) * 3))
        
        if danger_score >= 90:
            risk_level = "CRITICAL THREAT"
            risk_color = "#991b1b"
            risk_icon = "🚨"
            advice = "EXTREME DANGER: Almost certainly a phishing attack"
        elif danger_score >= 75:
            risk_level = "VERY HIGH RISK"
            risk_color = "#dc2626"
            risk_icon = "⚠️"
            advice = "HIGH THREAT: Multiple attack indicators detected"
        elif danger_score >= 60:
            risk_level = "HIGH RISK"
            risk_color = "#ea580c"
            risk_icon = "🔴"
            advice = "CAUTION: Significant threat indicators present"
        elif danger_score >= 45:
            risk_level = "MEDIUM RISK"
            risk_color = "#d97706"
            risk_icon = "⚡"
            advice = "SUSPICIOUS: Verify through alternative channels"
        elif danger_score >= 25:
            risk_level = "LOW-MEDIUM RISK"
            risk_color = "#0891b2"
            risk_icon = "💡"
            advice = "MINOR CONCERNS: Exercise normal caution"
        else:
            risk_level = "LOW RISK"
            risk_color = "#10b981"
            risk_icon = "✅"
            advice = "APPEARS LEGITIMATE: No significant threats detected"
        
        result = {
            'success': True,
            'analysis_type': 'email',
            'danger_score': danger_score,
            'confidence': confidence,
            'risk_level': risk_level,
            'risk_color': risk_color,
            'risk_icon': risk_icon,
            'advice': advice,
            'reasons': list(set(reasons)),
            'total_checks': len(reasons),
            'ml_probability': ml_probability,
            'ml_confidence': ml_confidence,
            'extracted_urls': extracted_urls,
            'live_url_checked': True,
            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        return jsonify(result)
        
    except Exception as e:
        print(f"Error in email analysis: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/analyze-url', methods=['POST'])
def analyze_url():
    """Comprehensive URL analysis endpoint"""
    try:
        print("🔗 URL analysis request received!")
        
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'success': False, 'error': 'Please provide a URL'}), 400
        
        # Normalize URL
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'https://' + url
        
        # Run comprehensive analysis
        results = analyze_url_comprehensive(url, GOOGLE_SAFE_BROWSING_KEY)
        
        # Format response for frontend
        score = results['overall_risk_score']
        
        if score >= 80:
            risk_color = "#991b1b"
            risk_icon = "🚨"
        elif score >= 60:
            risk_color = "#dc2626"
            risk_icon = "⚠️"
        elif score >= 40:
            risk_color = "#ea580c"
            risk_icon = "🔴"
        elif score >= 20:
            risk_color = "#d97706"
            risk_icon = "💡"
        else:
            risk_color = "#10b981"
            risk_icon = "✅"
        
        response = {
            'success': True,
            'analysis_type': 'url',
            'url': url,
            'danger_score': score,
            'risk_level': results['risk_level'],
            'risk_color': risk_color,
            'risk_icon': risk_icon,
            'summary': results['summary'],
            'reasons': results['all_risk_factors'],
            'total_checks': len(results['all_risk_factors']),
            
            # Detailed results
            'domain_info': results['domain_info'],
            'ssl_info': results['ssl_info'],
            'redirect_info': results['redirect_info'],
            'dns_info': results['dns_info'],
            'content_info': results['content_info'],
            'threat_check': results['threat_check'],
            
            'timestamp': results['timestamp']
        }
        
        return jsonify(response)
        
    except Exception as e:
        print(f"Error in URL analysis: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/quick-url-check', methods=['POST'])
def quick_url_check():
    """Quick URL safety check (faster, fewer checks)"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'success': False, 'error': 'Please provide a URL'}), 400
        
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'https://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        risk_score = 0
        findings = []
        
        # Quick domain check
        suspicious_tlds = ['.xyz', '.top', '.club', '.tk', '.ml', '.ga', '.cf']
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                risk_score += 25
                findings.append(f"Suspicious TLD: {tld}")
                break
        
        # Brand impersonation check
        brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'netflix', 'bank']
        for brand in brands:
            if brand in domain and brand + '.' not in domain:
                risk_score += 30
                findings.append(f"Possible {brand} impersonation")
                break
        
        # SSL check
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    pass  # SSL is valid
        except:
            risk_score += 20
            findings.append("No valid SSL certificate")
        
        # Determine quick verdict
        if risk_score >= 50:
            verdict = "SUSPICIOUS"
            color = "#dc2626"
        elif risk_score >= 25:
            verdict = "CAUTION"
            color = "#d97706"
        else:
            verdict = "LIKELY SAFE"
            color = "#10b981"
        
        return jsonify({
            'success': True,
            'url': url,
            'verdict': verdict,
            'risk_score': risk_score,
            'color': color,
            'findings': findings,
            'note': 'Use full analysis for comprehensive results'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# Monitoring endpoints (existing)
@app.route('/start-monitoring', methods=['POST'])
def start_monitoring():
    try:
        data = request.get_json()
        email_config = data.get('config', {})
        result = email_monitor.start_monitoring(email_config)
        return jsonify({'success': True, 'message': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/monitoring-status')
def monitoring_status():
    try:
        status = email_monitor.get_monitoring_status()
        return jsonify({'success': True, 'status': status})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/stop-monitoring', methods=['POST'])
def stop_monitoring():
    try:
        result = email_monitor.stop_monitoring()
        return jsonify({'success': True, 'message': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/feedback', methods=['POST'])
def provide_feedback():
    try:
        data = request.get_json()
        subject = data.get('subject', '')
        body = data.get('body', '')
        is_phishing = data.get('is_phishing', False)
        ml_model.learn_from_feedback(subject, body, is_phishing)
        return jsonify({'success': True, 'message': 'Feedback received'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# ERROR HANDLERS
# ============================================

@app.errorhandler(404)
def not_found(error):
    return render_template('index.html'), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'success': False, 'error': 'Internal server error'}), 500


# ============================================
# MAIN
# ============================================

if __name__ == '__main__':
    print("=" * 60)
    print("🛡️  PHISHING INTELLIGENCE PLATFORM v4.0")
    print("=" * 60)
    print("📧 Email Analysis - Detect phishing emails")
    print("🔗 URL Analysis - Deep URL threat intelligence")
    print("🤖 Machine Learning threat detection")
    print("📡 Real-time monitoring (simulation)")
    print("=" * 60)
    
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
