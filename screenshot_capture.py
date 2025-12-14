"""
Screenshot Capture Module v2
Captures webpage screenshots safely without visiting the site directly
Uses multiple free screenshot APIs with better fallbacks
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
        # Free screenshot APIs (no API key required) - ordered by reliability
        self.apis = [
            {
                'name': 'urlbox-free',
                'url': 'https://api.urlbox.io/v1/render?url={url}&width=1280&height=800&format=png',
                'method': 'redirect'
            },
            {
                'name': 'screenshot-machine',
                'url': 'https://api.screenshotmachine.com?device=desktop&dimension=1024x768&format=png&url={url}',
                'method': 'redirect'
            },
            {
                'name': 'thum.io',
                'url': 'https://image.thum.io/get/width/1280/crop/720/noanimate/{url}',
                'method': 'redirect'
            },
            {
                'name': 'pagepeeker',
                'url': 'https://free.pagepeeker.com/v2/thumbs.php?size=x&url={url}',
                'method': 'redirect'
            },
            {
                'name': 's.wordpress',
                'url': 'https://s.wordpress.com/mshots/v1/{url}?w=1280&h=960',
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
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
        except:
            pass
    
    def capture(self, url, timeout=20):
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
        
        try:
            if os.path.exists(cache_file):
                cache_age = time.time() - os.path.getmtime(cache_file)
                if cache_age < 3600:  # 1 hour cache
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
                    # API returns image directly or via redirect
                    response = requests.get(
                        api_url, 
                        timeout=timeout, 
                        stream=True,
                        headers={
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                        },
                        allow_redirects=True
                    )
                    
                    if response.status_code == 200:
                        content_type = response.headers.get('Content-Type', '')
                        
                        if 'image' in content_type:
                            img_data = response.content
                            
                            # Verify it's actually an image (check PNG/JPEG magic bytes)
                            if img_data[:4] == b'\x89PNG' or img_data[:2] == b'\xff\xd8':
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
                        
                        # Some APIs return a redirect URL to the image
                        elif response.url != api_url:
                            result['success'] = True
                            result['screenshot_url'] = response.url
                            result['api_used'] = api['name']
                            return result
                    
                    # If status is 200 but not an image, try returning the URL directly
                    # (some services generate on-demand)
                    if api['name'] in ['thum.io', 's.wordpress', 'pagepeeker']:
                        result['success'] = True
                        result['screenshot_url'] = api_url
                        result['api_used'] = api['name']
                        return result
                
                elif api['method'] == 'json':
                    # API returns JSON with screenshot URL
                    response = requests.get(
                        api_url, 
                        timeout=timeout,
                        headers={
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                        }
                    )
                    
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
            except requests.RequestException:
                continue
            except Exception as e:
                continue
        
        # If all APIs fail, return a fallback thumbnail URL that generates on-demand
        fallback_url = f'https://image.thum.io/get/width/1280/crop/800/{encoded_url}'
        result['success'] = True
        result['screenshot_url'] = fallback_url
        result['api_used'] = 'thum.io-fallback'
        result['note'] = 'Using fallback service - image may take a moment to generate'
        
        return result
    
    def get_thumbnail_url(self, url):
        """Get a direct thumbnail URL (for embedding in HTML)"""
        if not url.startswith('http'):
            url = 'https://' + url
        
        encoded_url = quote(url, safe='')
        
        # Return WordPress mshots URL - very reliable
        return f'https://s.wordpress.com/mshots/v1/{encoded_url}?w=600&h=450'
    
    def analyze_screenshot_safety(self, url):
        """
        Analyze if it's safe to take a screenshot of this URL
        Returns warnings if the URL looks suspicious
        """
        warnings = []
        
        url_lower = url.lower()
        
        # Check for suspicious patterns
        if 'login' in url_lower or 'signin' in url_lower or 'auth' in url_lower:
            warnings.append('URL contains login/auth page - may be credential harvesting')
        
        if any(ext in url_lower for ext in ['.exe', '.zip', '.rar', '.js', '.msi']):
            warnings.append('URL points to downloadable file')
        
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.pw', '.cc']
        for tld in suspicious_tlds:
            if url_lower.endswith(tld) or f'{tld}/' in url_lower:
                warnings.append(f'Suspicious TLD: {tld}')
                break
        
        # Check for IP address
        import re
        if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
            warnings.append('URL uses IP address instead of domain')
        
        # Check for very long URLs (common in phishing)
        if len(url) > 200:
            warnings.append('Unusually long URL')
        
        # Check for data URIs
        if url_lower.startswith('data:'):
            warnings.append('Data URI detected - cannot screenshot')
        
        return {
            'safe_to_preview': len(warnings) < 3,  # Allow preview with some warnings
            'warnings': warnings,
            'warning_count': len(warnings)
        }


# Singleton instance
_screenshot_capture = None

def get_screenshot_capture():
    global _screenshot_capture
    if _screenshot_capture is None:
        _screenshot_capture = ScreenshotCapture()
    return _screenshot_capture
