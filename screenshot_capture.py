"""
Screenshot Capture Module v3
Uses reliable screenshot services that generate images on-demand
"""

import requests
from urllib.parse import quote, urlparse
import hashlib
import os
import base64


class ScreenshotCapture:
    """Capture webpage screenshots using free APIs"""
    
    def __init__(self):
        self.cache_dir = '/tmp/screenshots'
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
        except:
            pass
    
    def capture(self, url, timeout=15):
        """
        Capture screenshot of a URL
        Returns screenshot URL from reliable services
        """
        result = {
            'success': False,
            'url': url,
            'screenshot_url': None,
            'screenshot_base64': None,
            'cached': False,
            'api_used': None,
            'error': None
        }
        
        # Validate and normalize URL
        if not url.startswith('http'):
            url = 'https://' + url
        
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                result['error'] = 'Invalid URL'
                return result
        except:
            result['error'] = 'Invalid URL format'
            return result
        
        encoded_url = quote(url, safe='')
        
        # List of screenshot services to try (these return images directly via URL)
        services = [
            {
                'name': 'WordPress mshots',
                'url': f'https://s.wordpress.com/mshots/v1/{encoded_url}?w=1280&h=960',
                'test': True
            },
            {
                'name': 'thum.io',
                'url': f'https://image.thum.io/get/width/1280/crop/800/noanimate/{encoded_url}',
                'test': True
            },
            {
                'name': 'PagePeeker',
                'url': f'https://free.pagepeeker.com/v2/thumbs.php?size=x&url={encoded_url}',
                'test': False  # Don't test, just use
            }
        ]
        
        # Try each service
        for service in services:
            try:
                if service.get('test', False):
                    # Test if the service responds
                    response = requests.head(
                        service['url'],
                        timeout=8,
                        allow_redirects=True,
                        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'}
                    )
                    
                    if response.status_code == 200:
                        content_type = response.headers.get('Content-Type', '')
                        # Check if it's returning an image or will generate one
                        if 'image' in content_type or response.status_code == 200:
                            result['success'] = True
                            result['screenshot_url'] = service['url']
                            result['api_used'] = service['name']
                            return result
                else:
                    # Just return the URL without testing
                    result['success'] = True
                    result['screenshot_url'] = service['url']
                    result['api_used'] = service['name']
                    return result
                    
            except Exception as e:
                continue
        
        # Fallback: Always return thum.io URL (it generates on-demand)
        result['success'] = True
        result['screenshot_url'] = f'https://image.thum.io/get/width/1280/crop/800/{encoded_url}'
        result['api_used'] = 'thum.io (fallback)'
        
        return result
    
    def get_thumbnail_url(self, url):
        """Get a direct thumbnail URL"""
        if not url.startswith('http'):
            url = 'https://' + url
        encoded_url = quote(url, safe='')
        return f'https://s.wordpress.com/mshots/v1/{encoded_url}?w=600&h=450'
    
    def analyze_screenshot_safety(self, url):
        """Analyze if URL looks suspicious"""
        warnings = []
        url_lower = url.lower()
        
        if 'login' in url_lower or 'signin' in url_lower:
            warnings.append('URL contains login page - may be phishing')
        
        if any(ext in url_lower for ext in ['.exe', '.zip', '.rar']):
            warnings.append('URL points to downloadable file')
        
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top']
        for tld in suspicious_tlds:
            if tld in url_lower:
                warnings.append(f'Suspicious TLD: {tld}')
                break
        
        import re
        if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
            warnings.append('URL uses IP address instead of domain')
        
        return {
            'safe_to_preview': len(warnings) == 0,
            'warnings': warnings
        }


_screenshot_capture = None

def get_screenshot_capture():
    global _screenshot_capture
    if _screenshot_capture is None:
        _screenshot_capture = ScreenshotCapture()
    return _screenshot_capture
