"""
Screenshot Capture Module
Captures webpage screenshots safely without visiting the site directly
Uses free screenshot APIs
"""

import requests
import base64
from urllib.parse import quote, urlparse
import hashlib
import os
import time


class ScreenshotCapture:
    """Capture webpage screenshots using free APIs"""
    
    def __init__(self):
        # Free screenshot APIs (no API key required)
        self.apis = [
            {
                'name': 'thum.io',
                'url': 'https://image.thum.io/get/width/1280/crop/720/noanimate/{url}',
                'method': 'redirect'  # Returns image directly
            },
            {
                'name': 'screenshot.screenshotapi.net',
                'url': 'https://shot.screenshotapi.net/screenshot?url={url}&full_page=false&output=image&file_type=png&wait_for_event=load',
                'method': 'redirect'
            },
            {
                'name': 'microlink',
                'url': 'https://api.microlink.io?url={url}&screenshot=true&meta=false&embed=screenshot.url',
                'method': 'json',
                'json_path': ['data', 'screenshot', 'url']
            }
        ]
        
        self.cache_dir = '/tmp/screenshots'
        os.makedirs(self.cache_dir, exist_ok=True)
    
    def capture(self, url, timeout=15):
        """
        Capture screenshot of a URL
        Returns: dict with success status, image data or URL, and metadata
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
        
        # Validate URL
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
        
        # Check cache first
        cache_key = hashlib.md5(url.encode()).hexdigest()
        cache_file = os.path.join(self.cache_dir, f'{cache_key}.png')
        
        if os.path.exists(cache_file):
            cache_age = time.time() - os.path.getmtime(cache_file)
            if cache_age < 3600:  # 1 hour cache
                try:
                    with open(cache_file, 'rb') as f:
                        img_data = f.read()
                    result['success'] = True
                    result['screenshot_base64'] = base64.b64encode(img_data).decode('utf-8')
                    result['cached'] = True
                    return result
                except:
                    pass
        
        # Try each API
        encoded_url = quote(url, safe='')
        
        for api in self.apis:
            try:
                api_url = api['url'].format(url=encoded_url)
                
                if api['method'] == 'redirect':
                    # API returns image directly
                    response = requests.get(api_url, timeout=timeout, stream=True)
                    
                    if response.status_code == 200:
                        content_type = response.headers.get('Content-Type', '')
                        if 'image' in content_type:
                            img_data = response.content
                            
                            # Cache it
                            try:
                                with open(cache_file, 'wb') as f:
                                    f.write(img_data)
                            except:
                                pass
                            
                            result['success'] = True
                            result['screenshot_base64'] = base64.b64encode(img_data).decode('utf-8')
                            result['api_used'] = api['name']
                            return result
                        else:
                            # It's a redirect URL, return it
                            result['success'] = True
                            result['screenshot_url'] = api_url
                            result['api_used'] = api['name']
                            return result
                
                elif api['method'] == 'json':
                    # API returns JSON with screenshot URL
                    response = requests.get(api_url, timeout=timeout)
                    
                    if response.status_code == 200:
                        data = response.json()
                        
                        # Navigate JSON path
                        screenshot_url = data
                        for key in api['json_path']:
                            if isinstance(screenshot_url, dict):
                                screenshot_url = screenshot_url.get(key)
                            else:
                                screenshot_url = None
                                break
                        
                        if screenshot_url:
                            result['success'] = True
                            result['screenshot_url'] = screenshot_url
                            result['api_used'] = api['name']
                            return result
                            
            except requests.Timeout:
                continue
            except Exception as e:
                continue
        
        result['error'] = 'All screenshot services failed. The site may be blocking automated access.'
        return result
    
    def get_thumbnail_url(self, url):
        """Get a direct thumbnail URL (for embedding in HTML)"""
        if not url.startswith('http'):
            url = 'https://' + url
        
        encoded_url = quote(url, safe='')
        
        # Return thum.io URL - it's reliable and returns image directly
        return f'https://image.thum.io/get/width/600/crop/400/noanimate/{encoded_url}'
    
    def analyze_screenshot_safety(self, url):
        """
        Analyze if it's safe to take a screenshot of this URL
        Returns warnings if the URL looks suspicious
        """
        warnings = []
        
        url_lower = url.lower()
        
        # Check for suspicious patterns
        if 'login' in url_lower or 'signin' in url_lower:
            warnings.append('URL contains login page - may be phishing')
        
        if any(ext in url_lower for ext in ['.exe', '.zip', '.rar', '.js']):
            warnings.append('URL points to downloadable file')
        
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top']
        for tld in suspicious_tlds:
            if tld in url_lower:
                warnings.append(f'Suspicious TLD: {tld}')
                break
        
        # Check for IP address
        import re
        if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
            warnings.append('URL uses IP address instead of domain')
        
        return {
            'safe_to_preview': len(warnings) == 0,
            'warnings': warnings
        }


# Singleton instance
_screenshot_capture = None

def get_screenshot_capture():
    global _screenshot_capture
    if _screenshot_capture is None:
        _screenshot_capture = ScreenshotCapture()
    return _screenshot_capture
