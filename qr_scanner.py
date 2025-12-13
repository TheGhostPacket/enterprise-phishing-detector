"""
QR Code Scanner Module
Extract and analyze URLs from QR code images
"""

import cv2
import numpy as np
from pyzbar import pyzbar
from PIL import Image
import io
import base64
import re


class QRCodeScanner:
    def __init__(self):
        self.url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
    
    def decode_qr_from_base64(self, base64_string):
        """Decode QR code from base64 image string"""
        try:
            # Remove data URL prefix if present
            if 'base64,' in base64_string:
                base64_string = base64_string.split('base64,')[1]
            
            # Decode base64 to bytes
            image_bytes = base64.b64decode(base64_string)
            
            # Convert to PIL Image
            image = Image.open(io.BytesIO(image_bytes))
            
            return self.decode_qr_from_image(image)
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to process image: {str(e)}'
            }
    
    def decode_qr_from_file(self, file_path):
        """Decode QR code from file path"""
        try:
            image = Image.open(file_path)
            return self.decode_qr_from_image(image)
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to read file: {str(e)}'
            }
    
    def decode_qr_from_bytes(self, image_bytes):
        """Decode QR code from bytes"""
        try:
            image = Image.open(io.BytesIO(image_bytes))
            return self.decode_qr_from_image(image)
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to process image bytes: {str(e)}'
            }
    
    def decode_qr_from_image(self, pil_image):
        """Decode QR code from PIL Image object"""
        try:
            # Convert to RGB if necessary
            if pil_image.mode != 'RGB':
                pil_image = pil_image.convert('RGB')
            
            # Convert PIL to OpenCV format
            cv_image = cv2.cvtColor(np.array(pil_image), cv2.COLOR_RGB2BGR)
            
            # Try multiple methods to decode
            decoded_objects = []
            
            # Method 1: Direct decode
            decoded_objects = pyzbar.decode(cv_image)
            
            # Method 2: Try with grayscale if no results
            if not decoded_objects:
                gray = cv2.cvtColor(cv_image, cv2.COLOR_BGR2GRAY)
                decoded_objects = pyzbar.decode(gray)
            
            # Method 3: Try with threshold if still no results
            if not decoded_objects:
                _, thresh = cv2.threshold(gray, 127, 255, cv2.THRESH_BINARY)
                decoded_objects = pyzbar.decode(thresh)
            
            # Method 4: Try with adaptive threshold
            if not decoded_objects:
                adaptive = cv2.adaptiveThreshold(
                    gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
                    cv2.THRESH_BINARY, 11, 2
                )
                decoded_objects = pyzbar.decode(adaptive)
            
            if not decoded_objects:
                return {
                    'success': False,
                    'error': 'No QR code found in image. Please ensure the QR code is clear and properly visible.'
                }
            
            # Process decoded data
            results = []
            for obj in decoded_objects:
                data = obj.data.decode('utf-8')
                qr_type = obj.type
                
                # Check if it's a URL
                is_url = bool(self.url_pattern.match(data))
                
                # Analyze the content
                analysis = self._analyze_qr_content(data)
                
                results.append({
                    'data': data,
                    'type': qr_type,
                    'is_url': is_url,
                    'analysis': analysis
                })
            
            return {
                'success': True,
                'count': len(results),
                'results': results
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to decode QR code: {str(e)}'
            }
    
    def _analyze_qr_content(self, data):
        """Analyze QR code content for suspicious patterns"""
        analysis = {
            'content_type': 'unknown',
            'risk_indicators': [],
            'preliminary_risk': 'low'
        }
        
        data_lower = data.lower()
        
        # Determine content type
        if self.url_pattern.match(data):
            analysis['content_type'] = 'url'
            
            # Check for suspicious URL patterns
            suspicious_patterns = [
                ('http://', 'Uses insecure HTTP protocol'),
                ('bit.ly', 'Uses URL shortener (bit.ly)'),
                ('tinyurl', 'Uses URL shortener (tinyurl)'),
                ('t.co', 'Uses URL shortener (t.co)'),
                ('.xyz', 'Suspicious TLD (.xyz)'),
                ('.top', 'Suspicious TLD (.top)'),
                ('.club', 'Suspicious TLD (.club)'),
                ('.tk', 'Free/suspicious TLD (.tk)'),
                ('.ml', 'Free/suspicious TLD (.ml)'),
                ('login', 'Contains "login" - may be credential harvesting'),
                ('verify', 'Contains "verify" - common phishing keyword'),
                ('secure-', 'Contains "secure-" - potential brand impersonation'),
                ('account-', 'Contains "account-" - potential brand impersonation'),
                ('update-', 'Contains "update-" - potential brand impersonation'),
                ('paypal', 'References PayPal - verify authenticity'),
                ('amazon', 'References Amazon - verify authenticity'),
                ('microsoft', 'References Microsoft - verify authenticity'),
                ('apple', 'References Apple - verify authenticity'),
                ('google', 'References Google - verify authenticity'),
                ('bank', 'References banking - verify authenticity'),
            ]
            
            for pattern, message in suspicious_patterns:
                if pattern in data_lower:
                    analysis['risk_indicators'].append(message)
            
            # Check for IP address instead of domain
            ip_pattern = r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            if re.match(ip_pattern, data):
                analysis['risk_indicators'].append('Uses IP address instead of domain name')
            
            # Check for excessive subdomains
            try:
                from urllib.parse import urlparse
                parsed = urlparse(data)
                subdomain_count = parsed.netloc.count('.')
                if subdomain_count > 3:
                    analysis['risk_indicators'].append(f'Excessive subdomains ({subdomain_count} levels)')
            except:
                pass
                
        elif data.startswith('tel:') or data.startswith('TEL:'):
            analysis['content_type'] = 'phone'
        elif data.startswith('mailto:') or data.startswith('MAILTO:'):
            analysis['content_type'] = 'email'
        elif data.startswith('WIFI:'):
            analysis['content_type'] = 'wifi'
            analysis['risk_indicators'].append('WiFi configuration - be cautious connecting to unknown networks')
        elif data.startswith('BEGIN:VCARD'):
            analysis['content_type'] = 'contact'
        elif data.startswith('bitcoin:') or data.startswith('ethereum:'):
            analysis['content_type'] = 'cryptocurrency'
            analysis['risk_indicators'].append('Cryptocurrency address - verify before sending funds')
        else:
            analysis['content_type'] = 'text'
        
        # Determine preliminary risk level
        if len(analysis['risk_indicators']) >= 3:
            analysis['preliminary_risk'] = 'high'
        elif len(analysis['risk_indicators']) >= 1:
            analysis['preliminary_risk'] = 'medium'
        else:
            analysis['preliminary_risk'] = 'low'
        
        return analysis


# Fallback scanner without OpenCV (uses only pyzbar with PIL)
class SimpleQRScanner:
    """Simpler QR scanner that doesn't require OpenCV"""
    
    def __init__(self):
        self.url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
    
    def decode_qr_from_base64(self, base64_string):
        """Decode QR code from base64 image string"""
        try:
            if 'base64,' in base64_string:
                base64_string = base64_string.split('base64,')[1]
            
            image_bytes = base64.b64decode(base64_string)
            image = Image.open(io.BytesIO(image_bytes))
            
            # Use pyzbar directly on PIL image
            decoded_objects = pyzbar.decode(image)
            
            if not decoded_objects:
                # Try converting to grayscale
                gray_image = image.convert('L')
                decoded_objects = pyzbar.decode(gray_image)
            
            if not decoded_objects:
                return {
                    'success': False,
                    'error': 'No QR code found in image'
                }
            
            results = []
            for obj in decoded_objects:
                data = obj.data.decode('utf-8')
                is_url = bool(self.url_pattern.match(data))
                
                results.append({
                    'data': data,
                    'type': obj.type,
                    'is_url': is_url
                })
            
            return {
                'success': True,
                'count': len(results),
                'results': results
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }


def get_qr_scanner():
    """Get the best available QR scanner"""
    try:
        import cv2
        return QRCodeScanner()
    except ImportError:
        return SimpleQRScanner()
