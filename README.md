# 🛡️ Phishing Intelligence Platform v4.0

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/Flask-2.3+-green.svg" alt="Flask">
  <img src="https://img.shields.io/badge/Security-Threat%20Intelligence-red.svg" alt="Security">
</div>

<div align="center">
  <h3>🔍 Comprehensive Email & URL Threat Analysis Platform 🔍</h3>
  <p><em>Built by The Ghost Packet | Cybersecurity Portfolio Project</em></p>
</div>

---

## 🌟 Overview

A comprehensive phishing intelligence platform that combines **email analysis**, **deep URL threat intelligence**, and **machine learning** to identify potential security threats. Analyze suspicious emails and URLs to protect yourself from phishing attacks.

## ⚡ Features

### 📧 Email Threat Analysis
- **Sender Verification** - Detects spoofed sender addresses
- **Suspicious Pattern Detection** - Identifies phishing language patterns
- **Urgency Tactic Analysis** - Flags pressure tactics
- **URL Extraction** - Automatically extracts and analyzes embedded URLs
- **ML-Based Classification** - Machine learning threat scoring

### 🔗 URL Threat Intelligence (NEW!)
- **Domain Intelligence** - WHOIS lookup, domain age, registrar info
- **SSL Certificate Analysis** - Issuer, validity, expiration, security assessment
- **Redirect Chain Mapping** - Tracks all URL redirects and hops
- **DNS Record Analysis** - A, MX, TXT, NS record inspection
- **Content Analysis** - Detects login forms, password fields, sensitive data requests
- **Brand Impersonation Detection** - Identifies fake brand domains
- **Typosquatting Detection** - Catches lookalike domains
- **Quick Check Mode** - Fast preliminary safety verdict

### 📡 Real-time Monitoring (Simulation)
- **Email Monitoring Dashboard** - Simulated inbox monitoring
- **Threat Alerts** - Real-time suspicious activity notifications
- **Statistics Tracking** - Monitor processed emails and blocked threats

## 🛠️ Technology Stack

- **Backend**: Python 3.11, Flask
- **Frontend**: HTML5, CSS3, JavaScript
- **Security**: python-whois, dnspython, SSL analysis
- **AI/ML**: Custom pattern-based machine learning

## 📁 Project Structure

```
phishing-detector/
├── app.py                 # Main Flask application
├── url_analyzer.py        # URL analysis module
├── requirements.txt       # Python dependencies
├── Procfile              # Render deployment config
├── templates/
│   └── index.html        # Main dashboard template
└── static/
    ├── css/
    │   └── style.css     # Styling
    └── js/
        └── app.js        # Frontend logic
```

## 🚀 Quick Start

### Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/phishing-intelligence-platform.git
   cd phishing-intelligence-platform
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**
   ```bash
   python app.py
   ```

5. **Open in browser**
   ```
   http://localhost:5000
   ```

### Deploy to Render

1. Push code to GitHub
2. Create new Web Service on Render
3. Connect your repository
4. Render will auto-detect Python and use the Procfile

## 📖 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main dashboard |
| `/analyze` | POST | Analyze email for phishing |
| `/analyze-url` | POST | Deep URL analysis |
| `/quick-url-check` | POST | Quick URL safety check |
| `/start-monitoring` | POST | Start email monitoring |
| `/stop-monitoring` | POST | Stop email monitoring |
| `/monitoring-status` | GET | Get monitoring status |
| `/feedback` | POST | Submit analysis feedback |

## 🔍 URL Analysis Checks

The URL analyzer performs these comprehensive checks:

1. **Domain Intelligence**
   - WHOIS data lookup
   - Domain age calculation
   - Registrar information
   - Name server analysis

2. **SSL/TLS Security**
   - Certificate validity
   - Issuer verification
   - Expiration checking
   - Certificate chain analysis

3. **Redirect Analysis**
   - Full redirect chain mapping
   - URL shortener detection
   - Cross-domain redirect flagging

4. **DNS Analysis**
   - A, MX, NS, TXT record lookup
   - Suspicious nameserver detection

5. **Content Analysis**
   - Login form detection
   - Password field identification
   - Sensitive info request detection
   - External form action flagging

6. **Reputation Checks**
   - Suspicious TLD detection
   - Brand impersonation patterns
   - Typosquatting detection

## ⚙️ Optional API Keys

For enhanced threat detection, you can add these environment variables:

```bash
GOOGLE_SAFE_BROWSING_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
```

## 🎯 Use Cases

- **Security Awareness Training** - Educate users about phishing
- **SOC Analysis** - Quick threat triage for security teams
- **Personal Protection** - Check suspicious links before clicking
- **Incident Response** - Analyze reported phishing attempts

## 📝 Example Usage

### Analyze a Suspicious Email
```json
POST /analyze
{
  "sender": "security@paypa1-verify.com",
  "subject": "URGENT: Your account has been suspended!",
  "body": "Click here to verify: http://paypa1-secure.xyz/verify"
}
```

### Analyze a Suspicious URL
```json
POST /analyze-url
{
  "url": "https://amaz0n-secure-login.xyz/verify"
}
```

## ⚠️ Disclaimer

This tool is for educational purposes and security awareness. Always verify suspicious communications through official channels. Never rely solely on automated tools for security decisions.

## 📄 License

MIT License - Feel free to use and modify for your own projects.

## 👨‍💻 Author

**The Ghost Packet**  
Cybersecurity Professional | Security+ (In Progress)  
[Portfolio](https://theghostpacket.com) | [LinkedIn](https://linkedin.com/in/yourprofile)

---

<div align="center">
  <p>⭐ Star this repo if you found it useful!</p>
  <p>🛡️ Stay safe from phishing attacks! 🛡️</p>
</div>
