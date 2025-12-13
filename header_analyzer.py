"""
Email Header Analyzer Module
Parse and analyze email headers for authentication and security
"""

import re
import email
from email import policy
from email.parser import Parser
import dns.resolver
from datetime import datetime


class EmailHeaderAnalyzer:
    def __init__(self):
        self.parser = Parser(policy=policy.default)
    
    def analyze_headers(self, raw_headers):
        """Analyze raw email headers"""
        result = {
            'success': False,
            'basic_info': {},
            'authentication': {
                'spf': {'status': 'not_found', 'details': None},
                'dkim': {'status': 'not_found', 'details': None},
                'dmarc': {'status': 'not_found', 'details': None}
            },
            'routing': [],
            'security_analysis': [],
            'risk_score': 0,
            'risk_level': 'unknown'
        }
        
        try:
            # Parse headers
            msg = self.parser.parsestr(raw_headers)
            
            # Extract basic info
            result['basic_info'] = self._extract_basic_info(msg)
            
            # Analyze authentication headers
            result['authentication'] = self._analyze_authentication(msg, raw_headers)
            
            # Analyze routing (Received headers)
            result['routing'] = self._analyze_routing(msg)
            
            # Security analysis
            result['security_analysis'] = self._security_analysis(msg, raw_headers, result)
            
            # Calculate risk score
            result['risk_score'], result['risk_level'] = self._calculate_risk(result)
            
            result['success'] = True
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _extract_basic_info(self, msg):
        """Extract basic email information"""
        info = {
            'from': None,
            'to': None,
            'subject': None,
            'date': None,
            'message_id': None,
            'reply_to': None,
            'return_path': None
        }
        
        info['from'] = msg.get('From', '')
        info['to'] = msg.get('To', '')
        info['subject'] = msg.get('Subject', '')
        info['date'] = msg.get('Date', '')
        info['message_id'] = msg.get('Message-ID', '')
        info['reply_to'] = msg.get('Reply-To', '')
        info['return_path'] = msg.get('Return-Path', '')
        
        return info
    
    def _analyze_authentication(self, msg, raw_headers):
        """Analyze SPF, DKIM, and DMARC"""
        auth = {
            'spf': {'status': 'not_found', 'details': None, 'raw': None},
            'dkim': {'status': 'not_found', 'details': None, 'raw': None},
            'dmarc': {'status': 'not_found', 'details': None, 'raw': None}
        }
        
        # Look for Authentication-Results header
        auth_results = msg.get('Authentication-Results', '')
        
        # Also check Received-SPF header
        received_spf = msg.get('Received-SPF', '')
        
        # Check ARC headers
        arc_auth = msg.get('ARC-Authentication-Results', '')
        
        combined_auth = f"{auth_results} {received_spf} {arc_auth}".lower()
        
        # SPF Analysis
        spf_patterns = [
            (r'spf=pass', 'pass'),
            (r'spf=fail', 'fail'),
            (r'spf=softfail', 'softfail'),
            (r'spf=neutral', 'neutral'),
            (r'spf=none', 'none'),
            (r'spf=temperror', 'temperror'),
            (r'spf=permerror', 'permerror')
        ]
        
        for pattern, status in spf_patterns:
            if re.search(pattern, combined_auth):
                auth['spf']['status'] = status
                auth['spf']['raw'] = received_spf or self._extract_auth_detail(auth_results, 'spf')
                break
        
        # DKIM Analysis
        dkim_patterns = [
            (r'dkim=pass', 'pass'),
            (r'dkim=fail', 'fail'),
            (r'dkim=neutral', 'neutral'),
            (r'dkim=none', 'none'),
            (r'dkim=temperror', 'temperror'),
            (r'dkim=permerror', 'permerror')
        ]
        
        for pattern, status in dkim_patterns:
            if re.search(pattern, combined_auth):
                auth['dkim']['status'] = status
                auth['dkim']['raw'] = self._extract_auth_detail(auth_results, 'dkim')
                break
        
        # Check for DKIM-Signature header
        dkim_sig = msg.get('DKIM-Signature', '')
        if dkim_sig and auth['dkim']['status'] == 'not_found':
            auth['dkim']['status'] = 'present'
            auth['dkim']['details'] = 'DKIM signature present but status unknown'
        
        # DMARC Analysis
        dmarc_patterns = [
            (r'dmarc=pass', 'pass'),
            (r'dmarc=fail', 'fail'),
            (r'dmarc=none', 'none'),
            (r'dmarc=bestguesspass', 'bestguesspass')
        ]
        
        for pattern, status in dmarc_patterns:
            if re.search(pattern, combined_auth):
                auth['dmarc']['status'] = status
                auth['dmarc']['raw'] = self._extract_auth_detail(auth_results, 'dmarc')
                break
        
        return auth
    
    def _extract_auth_detail(self, auth_results, auth_type):
        """Extract specific authentication detail from results"""
        pattern = rf'{auth_type}=[^\s;]+'
        match = re.search(pattern, auth_results, re.IGNORECASE)
        return match.group(0) if match else None
    
    def _analyze_routing(self, msg):
        """Analyze email routing from Received headers"""
        routing = []
        
        # Get all Received headers (they're in reverse order)
        received_headers = msg.get_all('Received', [])
        
        for i, header in enumerate(received_headers):
            hop = {
                'hop_number': len(received_headers) - i,
                'raw': header[:200] + '...' if len(header) > 200 else header,
                'from_server': None,
                'by_server': None,
                'timestamp': None,
                'suspicious': False,
                'notes': []
            }
            
            # Extract 'from' server
            from_match = re.search(r'from\s+([^\s]+)', header, re.IGNORECASE)
            if from_match:
                hop['from_server'] = from_match.group(1)
            
            # Extract 'by' server
            by_match = re.search(r'by\s+([^\s]+)', header, re.IGNORECASE)
            if by_match:
                hop['by_server'] = by_match.group(1)
            
            # Extract timestamp
            # Common formats: "Mon, 1 Jan 2024 12:00:00 +0000"
            date_patterns = [
                r';\s*(.+?\d{4}\s+\d{2}:\d{2}:\d{2}[^\(]*)',
                r'(\d{1,2}\s+\w{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2})',
            ]
            
            for pattern in date_patterns:
                date_match = re.search(pattern, header)
                if date_match:
                    hop['timestamp'] = date_match.group(1).strip()
                    break
            
            # Check for suspicious patterns
            suspicious_checks = [
                (r'localhost', 'Routes through localhost'),
                (r'127\.0\.0\.1', 'Routes through localhost IP'),
                (r'\.ru\b', 'Routes through Russian server'),
                (r'\.cn\b', 'Routes through Chinese server'),
                (r'unknown', 'Unknown server in route'),
            ]
            
            for pattern, note in suspicious_checks:
                if re.search(pattern, header, re.IGNORECASE):
                    hop['suspicious'] = True
                    hop['notes'].append(note)
            
            routing.append(hop)
        
        return routing
    
    def _security_analysis(self, msg, raw_headers, result):
        """Perform security analysis"""
        findings = []
        
        basic = result['basic_info']
        auth = result['authentication']
        
        # Check From vs Return-Path mismatch
        from_addr = basic.get('from', '')
        return_path = basic.get('return_path', '')
        
        from_domain = self._extract_domain(from_addr)
        return_domain = self._extract_domain(return_path)
        
        if from_domain and return_domain and from_domain != return_domain:
            findings.append({
                'severity': 'high',
                'finding': 'From and Return-Path domains do not match',
                'details': f"From: {from_domain}, Return-Path: {return_domain}",
                'recommendation': 'This is a strong indicator of spoofing'
            })
        
        # Check From vs Reply-To mismatch
        reply_to = basic.get('reply_to', '')
        reply_domain = self._extract_domain(reply_to)
        
        if reply_to and from_domain and reply_domain and from_domain != reply_domain:
            findings.append({
                'severity': 'medium',
                'finding': 'Reply-To domain differs from From domain',
                'details': f"From: {from_domain}, Reply-To: {reply_domain}",
                'recommendation': 'Replies may go to a different address than shown'
            })
        
        # Check SPF status
        if auth['spf']['status'] == 'fail':
            findings.append({
                'severity': 'high',
                'finding': 'SPF authentication failed',
                'details': 'Sender is not authorized to send from this domain',
                'recommendation': 'This email may be spoofed'
            })
        elif auth['spf']['status'] == 'softfail':
            findings.append({
                'severity': 'medium',
                'finding': 'SPF authentication soft-failed',
                'details': 'Sender may not be authorized',
                'recommendation': 'Treat with caution'
            })
        elif auth['spf']['status'] == 'not_found':
            findings.append({
                'severity': 'low',
                'finding': 'No SPF authentication results found',
                'details': 'Cannot verify sender authorization',
                'recommendation': 'Domain may not have SPF configured'
            })
        
        # Check DKIM status
        if auth['dkim']['status'] == 'fail':
            findings.append({
                'severity': 'high',
                'finding': 'DKIM authentication failed',
                'details': 'Email signature verification failed',
                'recommendation': 'Email may have been modified in transit or spoofed'
            })
        elif auth['dkim']['status'] == 'not_found':
            findings.append({
                'severity': 'low',
                'finding': 'No DKIM signature found',
                'details': 'Email is not digitally signed',
                'recommendation': 'Cannot verify email integrity'
            })
        
        # Check DMARC status
        if auth['dmarc']['status'] == 'fail':
            findings.append({
                'severity': 'high',
                'finding': 'DMARC authentication failed',
                'details': 'Email failed domain authentication policy',
                'recommendation': 'This email should be treated as suspicious'
            })
        
        # Check for suspicious routing
        suspicious_hops = [h for h in result['routing'] if h.get('suspicious')]
        if suspicious_hops:
            findings.append({
                'severity': 'medium',
                'finding': f'{len(suspicious_hops)} suspicious routing hop(s) detected',
                'details': ', '.join([n for h in suspicious_hops for n in h.get('notes', [])]),
                'recommendation': 'Email routing may be unusual'
            })
        
        # Check for X-Mailer or unusual headers
        x_mailer = msg.get('X-Mailer', '')
        if x_mailer:
            suspicious_mailers = ['PHPMailer', 'Swiftmailer', 'sendmail']
            for mailer in suspicious_mailers:
                if mailer.lower() in x_mailer.lower():
                    findings.append({
                        'severity': 'low',
                        'finding': f'Email sent using {mailer}',
                        'details': f'X-Mailer: {x_mailer}',
                        'recommendation': 'Common in automated/bulk email'
                    })
                    break
        
        # Check for missing Message-ID
        if not basic.get('message_id'):
            findings.append({
                'severity': 'medium',
                'finding': 'Missing Message-ID header',
                'details': 'Legitimate emails typically have a Message-ID',
                'recommendation': 'May indicate manually crafted email'
            })
        
        return findings
    
    def _extract_domain(self, email_string):
        """Extract domain from email address"""
        if not email_string:
            return None
        
        # Handle "Name <email@domain.com>" format
        match = re.search(r'[\w\.-]+@([\w\.-]+)', email_string)
        if match:
            return match.group(1).lower()
        
        return None
    
    def _calculate_risk(self, result):
        """Calculate overall risk score"""
        score = 0
        
        auth = result['authentication']
        findings = result['security_analysis']
        
        # Authentication scoring
        auth_scores = {
            'pass': 0,
            'fail': 30,
            'softfail': 15,
            'neutral': 5,
            'none': 10,
            'not_found': 5,
            'present': 0,
            'temperror': 10,
            'permerror': 15,
            'bestguesspass': 5
        }
        
        score += auth_scores.get(auth['spf']['status'], 5)
        score += auth_scores.get(auth['dkim']['status'], 5)
        score += auth_scores.get(auth['dmarc']['status'], 5)
        
        # Findings scoring
        severity_scores = {
            'high': 20,
            'medium': 10,
            'low': 5
        }
        
        for finding in findings:
            score += severity_scores.get(finding.get('severity', 'low'), 5)
        
        # Cap at 100
        score = min(score, 100)
        
        # Determine risk level
        if score >= 60:
            risk_level = 'high'
        elif score >= 30:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return score, risk_level
    
    def check_domain_records(self, domain):
        """Check SPF, DKIM, and DMARC records for a domain"""
        records = {
            'spf': None,
            'dmarc': None,
            'has_mx': False
        }
        
        try:
            # Check SPF (TXT record)
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                for record in txt_records:
                    txt_data = str(record).strip('"')
                    if txt_data.startswith('v=spf1'):
                        records['spf'] = txt_data
                        break
            except:
                pass
            
            # Check DMARC
            try:
                dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                for record in dmarc_records:
                    txt_data = str(record).strip('"')
                    if txt_data.startswith('v=DMARC1'):
                        records['dmarc'] = txt_data
                        break
            except:
                pass
            
            # Check MX records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                records['has_mx'] = len(list(mx_records)) > 0
            except:
                pass
                
        except Exception as e:
            records['error'] = str(e)
        
        return records
