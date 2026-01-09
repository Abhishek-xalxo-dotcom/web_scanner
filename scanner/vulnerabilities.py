import requests
import re
import time
from urllib.parse import urlparse, parse_qs
from scanner.payloads import SQLI_PAYLOADS, XSS_PAYLOADS, SQL_ERROR_PATTERNS
from database.models import add_finding

class VulnerabilityScanner:
    def __init__(self, scan_id, delay=0.5):
        self.scan_id = scan_id
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
    
    def _make_request(self, url, method='GET', params=None, data=None):
        """Make HTTP request with delay"""
        time.sleep(self.delay)
        
        try:
            if method.upper() == 'GET':
                return self.session.get(url, params=params, timeout=10, allow_redirects=True)
            else:
                return self.session.post(url, data=data, timeout=10, allow_redirects=True)
        except requests.RequestException as e:
            print(f"[Scanner] Request error: {e}")
            return None
    
    def test_sql_injection(self, url, method='GET', params=None, data=None):
        """Test for SQL injection vulnerabilities"""
        if method.upper() == 'GET':
            test_params = params
        else:
            test_params = data
        
        if not test_params:
            return []
        
        # Get baseline response
        baseline_response = self._make_request(url, method, params, data)
        if not baseline_response:
            return []
        
        baseline_text = baseline_response.text
        findings = []
        
        for param_name, param_value in test_params.items():
            if not param_name:
                continue
                
            for payload in SQLI_PAYLOADS[:8]:  # Limit to 8 payloads
                try:
                    # Create test parameters
                    if method.upper() == 'GET':
                        test_data = None
                        test_params_dict = params.copy() if params else {}
                        test_params_dict[param_name] = payload
                    else:
                        test_params_dict = None
                        test_data = data.copy() if data else {}
                        test_data[param_name] = payload
                    
                    # Send test request
                    response = self._make_request(url, method, test_params_dict, test_data)
                    if not response:
                        continue
                    
                    response_text = response.text
                    
                    # Check for SQL error patterns
                    for pattern in SQL_ERROR_PATTERNS:
                        if re.search(pattern, response_text, re.IGNORECASE):
                            # Verify it's not in baseline
                            if not re.search(pattern, baseline_text, re.IGNORECASE):
                                evidence = f"Payload triggered SQL error: {pattern[:50]}..."
                                add_finding(
                                    scan_id=self.scan_id,
                                    url=url,
                                    vulnerability_type='SQL Injection',
                                    parameter=param_name,
                                    evidence=evidence,
                                    severity='High',
                                    impact='Database compromise, data leakage',
                                    recommendation='Use parameterized queries and input validation'
                                )
                                findings.append(f"SQLi in {param_name}")
                                break
                    
                except Exception as e:
                    continue
        
        return findings
    
    def test_xss(self, url, method='GET', params=None, data=None):
        """Test for XSS vulnerabilities"""
        if method.upper() == 'GET':
            test_params = params
        else:
            test_params = data
        
        if not test_params:
            return []
        
        findings = []
        test_payloads = XSS_PAYLOADS[:5]  # Limit payloads
        
        for param_name in test_params:
            if not param_name:
                continue
                
            for payload in test_payloads:
                try:
                    if method.upper() == 'GET':
                        test_data = None
                        test_params_dict = params.copy() if params else {}
                        test_params_dict[param_name] = payload
                    else:
                        test_params_dict = None
                        test_data = data.copy() if data else {}
                        test_data[param_name] = payload
                    
                    response = self._make_request(url, method, test_params_dict, test_data)
                    if not response:
                        continue
                    
                    # Check if payload appears unescaped
                    if payload in response.text:
                        # Check for basic escaping
                        escaped = payload.replace('<', '&lt;').replace('>', '&gt;')
                        if escaped not in response.text:
                            evidence = f"XSS payload reflected: {payload[:30]}..."
                            add_finding(
                                scan_id=self.scan_id,
                                url=url,
                                vulnerability_type='XSS',
                                parameter=param_name,
                                evidence=evidence,
                                severity='Medium',
                                impact='Session hijacking, defacement',
                                recommendation='Implement output encoding and CSP'
                            )
                            findings.append(f"XSS in {param_name}")
                    
                except Exception as e:
                    continue
        
        return findings
    
    def check_security_headers(self, url):
        """Check for missing security headers"""
        findings = []
        
        try:
            response = self.session.head(url, timeout=5, allow_redirects=True)
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            security_headers = [
                ('content-security-policy', 'CSP', 'Medium'),
                ('x-frame-options', 'X-Frame-Options', 'Low'),
                ('strict-transport-security', 'HSTS', 'Medium'),
                ('x-content-type-options', 'X-Content-Type-Options', 'Low'),
                ('referrer-policy', 'Referrer-Policy', 'Low'),
            ]
            
            for header_key, header_name, severity in security_headers:
                if header_key not in headers:
                    add_finding(
                        scan_id=self.scan_id,
                        url=url,
                        vulnerability_type='Missing Header',
                        parameter=header_name,
                        evidence=f'{header_name} header missing',
                        severity=severity,
                        impact='Various security risks',
                        recommendation=f'Add {header_name} header with secure values'
                    )
                    findings.append(f"Missing {header_name}")
        
        except Exception as e:
            print(f"[Scanner] Header check error: {e}")
        
        return findings
    
    def check_cookie_security(self, url):
        """Check cookie security flags"""
        findings = []
        
        try:
            response = self.session.get(url, timeout=5)
            
            for cookie in response.cookies:
                cookie_str = str(cookie)
                
                checks = [
                    ('HttpOnly', 'Low', 'Cookie accessible via JavaScript'),
                    ('Secure', 'Medium' if url.startswith('https') else 'Low', 'Cookie transmitted insecurely'),
                    ('SameSite', 'Low', 'CSRF vulnerability'),
                ]
                
                for flag, severity, impact in checks:
                    if flag not in cookie_str:
                        add_finding(
                            scan_id=self.scan_id,
                            url=url,
                            vulnerability_type='Insecure Cookie',
                            parameter=cookie.name,
                            evidence=f'Missing {flag} flag',
                            severity=severity,
                            impact=impact,
                            recommendation=f'Add {flag} flag to cookie'
                        )
                        findings.append(f"Cookie {cookie.name} missing {flag}")
        
        except Exception as e:
            print(f"[Scanner] Cookie check error: {e}")
        
        return findings
    
    def scan_url(self, url):
        """Scan a single URL"""
        print(f"[Scanner] Scanning URL: {url}")
        
        findings = []
        
        # Parse URL for GET parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        simple_params = {k: v[0] for k, v in params.items() if v}
        
        # Test GET parameters
        if simple_params:
            findings.extend(self.test_sql_injection(url, 'GET', simple_params))
            findings.extend(self.test_xss(url, 'GET', simple_params))
        
        # Check headers and cookies
        findings.extend(self.check_security_headers(url))
        findings.extend(self.check_cookie_security(url))
        
        return findings
    
    def scan_form(self, form_data):
        """Scan a form"""
        url = form_data['action']
        method = form_data['method']
        
        # Create parameters from form inputs
        params = {}
        for input_field in form_data['inputs']:
            if input_field['name']:
                params[input_field['name']] = input_field['value'] or 'test'
        
        if not params:
            return []
        
        findings = []
        
        if method == 'get':
            findings.extend(self.test_sql_injection(url, 'GET', params))
            findings.extend(self.test_xss(url, 'GET', params))
        else:
            findings.extend(self.test_sql_injection(url, 'POST', None, params))
            findings.extend(self.test_xss(url, 'POST', None, params))
        
        return findings