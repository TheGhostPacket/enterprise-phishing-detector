"""
Phishing Intelligence Platform v5.0
Complete Email and URL Analysis Suite
"""

from flask import Flask, render_template, request, jsonify, send_file
import datetime, os, re, requests, socket, ssl, json, base64
from urllib.parse import urlparse
from url_analyzer import analyze_url_comprehensive
from header_analyzer import EmailHeaderAnalyzer
from history_feeds import ScanHistory, ThreatFeed, LearningCenter

try:
    from report_generator import PhishingReportGenerator
    REPORTS_ENABLED = True
except: REPORTS_ENABLED = False

try:
    from qr_scanner import get_qr_scanner
    qr_scanner = get_qr_scanner()
    QR_ENABLED = True
except Exception as e:
    print(f"QR Scanner disabled: {e}")
    QR_ENABLED = False

app = Flask(__name__)

GOOGLE_SAFE_BROWSING_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_KEY')
scan_history = ScanHistory()
threat_feed = ThreatFeed()
header_analyzer = EmailHeaderAnalyzer()
if REPORTS_ENABLED: report_generator = PhishingReportGenerator()

# ============================================
# EMAIL ANALYSIS
# ============================================
def check_live_url_safety(body):
    danger_score, reasons, urls = 0, [], []
    found = re.findall(r'http[s]?://[^\s<>"]+', body)
    for url in found[:3]:
        urls.append(url)
        domain = urlparse(url).netloc.lower()
        for p in ['phishing','scam','verify-','account-','login-','secure-']:
            if p in url.lower(): danger_score += 15; reasons.append(f"Suspicious pattern: {p}")
        try:
            r = requests.head(url, timeout=5, allow_redirects=False)
            if r.status_code in [301,302,307,308] and urlparse(r.headers.get('Location','')).netloc != domain:
                danger_score += 25; reasons.append("Redirects to different domain")
        except: pass
    return danger_score, reasons, urls

class PhishingMLModel:
    def __init__(self): self.trained = True
    def predict(self, subject, body):
        text = (subject + " " + body).lower()
        score = sum(20 for w in ['urgent','immediate','expires'] if w in text)
        score += sum(15 for w in ['money','prize','won','winner'] if w in text)
        score += sum(10 for w in ['click','verify','confirm','update'] if w in text)
        return min(score, 95), "High" if score > 70 else "Medium" if score > 40 else "Low"
    def learn(self, subject, body, is_phishing): pass

ml_model = PhishingMLModel()

def analyze_email(subject, sender, body):
    score, reasons = 0, []
    for word in ["urgent","winner","verify","suspended","confirm","security","password","login"]:
        if word in subject.lower(): score += 12; reasons.append(f"'{word}' in subject")
        if word in body.lower(): score += 6; reasons.append(f"'{word}' in body")
    for company in ["bank","paypal","amazon","microsoft","apple"]:
        if company in sender.lower():
            for free in ["gmail.com","yahoo.com","hotmail.com"]:
                if free in sender.lower(): score += 35; reasons.append(f"Claims {company} but uses {free}")
    url_score, url_reasons, urls = check_live_url_safety(body)
    score += url_score; reasons.extend(url_reasons)
    ml_prob, ml_conf = ml_model.predict(subject, body)
    if ml_prob > 60: score += int(ml_prob * 0.3)
    return min(score, 100), list(set(reasons)), ml_prob, ml_conf, urls

# ============================================
# ROUTES
# ============================================
@app.route('/')
def home(): return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_email_route():
    try:
        d = request.get_json()
        sender, subject, body = d.get('sender','').strip(), d.get('subject','').strip(), d.get('body','').strip()
        if not sender or not subject: return jsonify({'success': False, 'error': 'Provide sender and subject'}), 400
        score, reasons, ml_prob, ml_conf, urls = analyze_email(subject, sender, body)
        
        if score >= 80: level, color, icon, advice = "CRITICAL", "#991b1b", "🚨", "Extreme danger"
        elif score >= 60: level, color, icon, advice = "HIGH RISK", "#dc2626", "⚠️", "High threat"
        elif score >= 40: level, color, icon, advice = "MEDIUM", "#d97706", "⚡", "Suspicious"
        elif score >= 20: level, color, icon, advice = "LOW-MEDIUM", "#0891b2", "💡", "Minor concerns"
        else: level, color, icon, advice = "LOW", "#10b981", "✅", "Appears safe"
        
        result = {'success': True, 'danger_score': score, 'risk_level': level, 'risk_color': color, 'risk_icon': icon,
                  'advice': advice, 'reasons': reasons, 'ml_probability': ml_prob, 'ml_confidence': ml_conf,
                  'extracted_urls': urls, 'sender': sender, 'subject': subject, 'timestamp': datetime.datetime.now().isoformat()}
        scan_history.add_scan('email', f"{sender[:30]} - {subject[:30]}", result)
        return jsonify(result)
    except Exception as e: return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/analyze-url', methods=['POST'])
def analyze_url_route():
    try:
        url = request.get_json().get('url', '').strip()
        if not url: return jsonify({'success': False, 'error': 'Provide URL'}), 400
        if not url.startswith('http'): url = 'https://' + url
        
        results = analyze_url_comprehensive(url, GOOGLE_SAFE_BROWSING_KEY)
        score = results['overall_risk_score']
        
        if score >= 80: color, icon = "#991b1b", "🚨"
        elif score >= 60: color, icon = "#dc2626", "⚠️"
        elif score >= 40: color, icon = "#ea580c", "🔴"
        elif score >= 20: color, icon = "#d97706", "💡"
        else: color, icon = "#10b981", "✅"
        
        response = {'success': True, 'url': url, 'danger_score': score, 'risk_level': results['risk_level'],
                   'risk_color': color, 'risk_icon': icon, 'summary': results['summary'], 'reasons': results['all_risk_factors'],
                   'domain_info': results['domain_info'], 'ssl_info': results['ssl_info'], 'redirect_info': results['redirect_info'],
                   'dns_info': results['dns_info'], 'content_info': results['content_info'], 'timestamp': results['timestamp']}
        scan_history.add_scan('url', url[:50], response)
        return jsonify(response)
    except Exception as e: return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/quick-url-check', methods=['POST'])
def quick_check():
    try:
        url = request.get_json().get('url', '').strip()
        if not url: return jsonify({'success': False, 'error': 'Provide URL'}), 400
        if not url.startswith('http'): url = 'https://' + url
        domain = urlparse(url).netloc.lower()
        score, findings = 0, []
        
        for tld in ['.xyz','.top','.tk','.ml','.ga','.cf']:
            if domain.endswith(tld): score += 25; findings.append(f"Suspicious TLD: {tld}"); break
        for brand in ['paypal','amazon','apple','microsoft','google','bank']:
            if brand in domain and brand+'.' not in domain: score += 30; findings.append(f"Possible {brand} impersonation"); break
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as s:
                with ctx.wrap_socket(s, server_hostname=domain): pass
        except: score += 20; findings.append("No valid SSL")
        
        verdict = "SUSPICIOUS" if score >= 50 else "CAUTION" if score >= 25 else "LIKELY SAFE"
        color = "#dc2626" if score >= 50 else "#d97706" if score >= 25 else "#10b981"
        return jsonify({'success': True, 'url': url, 'verdict': verdict, 'risk_score': score, 'color': color, 'findings': findings, 'note': 'Use full analysis for details'})
    except Exception as e: return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/bulk-url-check', methods=['POST'])
def bulk_check():
    try:
        urls = request.get_json().get('urls', [])[:10]
        results = []
        for url in urls:
            url = url.strip()
            if not url: continue
            if not url.startswith('http'): url = 'https://' + url
            try:
                r = analyze_url_comprehensive(url, GOOGLE_SAFE_BROWSING_KEY)
                results.append({'url': url, 'risk_score': r['overall_risk_score'], 'risk_level': r['risk_level'], 'success': True})
            except: results.append({'url': url, 'success': False, 'error': 'Failed'})
        return jsonify({'success': True, 'results': results})
    except Exception as e: return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/expand-url', methods=['POST'])
def expand_url():
    try:
        url = request.get_json().get('url', '').strip()
        if not url.startswith('http'): url = 'https://' + url
        chain, current = [], url
        for _ in range(10):
            try:
                r = requests.head(current, allow_redirects=False, timeout=5)
                chain.append({'url': current, 'status': r.status_code})
                if r.status_code in [301,302,303,307,308]:
                    loc = r.headers.get('Location', '')
                    if loc:
                        if not loc.startswith('http'): loc = urlparse(current).scheme + '://' + urlparse(current).netloc + loc
                        current = loc
                    else: break
                else: break
            except: break
        return jsonify({'success': True, 'original_url': url, 'final_url': current, 'redirect_count': len(chain)-1, 'chain': chain})
    except Exception as e: return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/scan-qr', methods=['POST'])
def scan_qr():
    if not QR_ENABLED: return jsonify({'success': False, 'error': 'QR scanning unavailable'}), 400
    try:
        img = request.get_json().get('image', '')
        return jsonify(qr_scanner.decode_qr_from_base64(img))
    except Exception as e: return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/analyze-headers', methods=['POST'])
def analyze_headers():
    try:
        headers = request.get_json().get('headers', '')
        return jsonify(header_analyzer.analyze_headers(headers))
    except Exception as e: return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/generate-report', methods=['POST'])
def generate_report():
    if not REPORTS_ENABLED: return jsonify({'success': False, 'error': 'PDF reports unavailable'}), 400
    try:
        d = request.get_json()
        pdf = report_generator.generate_email_report(d['data']) if d.get('type') == 'email' else report_generator.generate_url_report(d['data'])
        return send_file(pdf, mimetype='application/pdf', as_attachment=True, download_name=f"report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
    except Exception as e: return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/history')
def get_history():
    try:
        return jsonify({'success': True, 'scans': scan_history.get_recent_scans(limit=request.args.get('limit', 20, type=int), scan_type=request.args.get('type')), 'stats': scan_history.get_stats()})
    except Exception as e: return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/history/search')
def search_history():
    return jsonify({'success': True, 'results': scan_history.search_scans(request.args.get('q', ''))})

@app.route('/history/clear', methods=['POST'])
def clear_history():
    scan_history.clear_history()
    return jsonify({'success': True})

@app.route('/threat-feed')
def get_threat_feed():
    return jsonify({'success': True, 'feed': threat_feed.get_combined_feed(limit=30)})

@app.route('/learning/tips')
def get_tips(): return jsonify({'success': True, 'tips': LearningCenter.get_phishing_tips()})

@app.route('/learning/types')
def get_types(): return jsonify({'success': True, 'types': LearningCenter.get_common_phishing_types()})

@app.route('/learning/actions')
def get_actions(): return jsonify({'success': True, 'actions': LearningCenter.get_what_to_do()})

@app.route('/feedback', methods=['POST'])
def feedback():
    d = request.get_json()
    ml_model.learn(d.get('subject',''), d.get('body',''), d.get('is_phishing', False))
    return jsonify({'success': True})

@app.route('/features')
def features():
    return jsonify({'success': True, 'features': {'pdf_reports': REPORTS_ENABLED, 'qr_scanner': QR_ENABLED}})

@app.errorhandler(404)
def not_found(e): return render_template('index.html'), 404

@app.errorhandler(500)
def error(e): return jsonify({'success': False, 'error': 'Server error'}), 500

if __name__ == '__main__':
    print("=" * 50)
    print("🛡️ PHISHING INTELLIGENCE PLATFORM v5.0")
    print("=" * 50)
    print(f"📄 PDF Reports: {'✅' if REPORTS_ENABLED else '❌'}")
    print(f"📱 QR Scanner: {'✅' if QR_ENABLED else '❌'}")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
