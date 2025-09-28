"""
Advanced Security Scanner Module for Cyber AI
Provides real vulnerability testing capabilities
"""

import requests
import socket
import ssl
import subprocess
import json
import re
import time
from datetime import datetime
from urllib.parse import urlparse, urljoin
import dns.resolver
import whois
from bs4 import BeautifulSoup
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import hashlib
import base64

class SecurityScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CyberAI-SecurityScanner/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        self.vulnerabilities = []
        self.scan_results = {}

    def scan_website(self, url):
        """Comprehensive website security scan"""
        print(f"🔍 Starting comprehensive security scan for: {url}")
        
        # Ensure URL has protocol
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        scan_results = {
            'url': url,
            'domain': domain,
            'scan_date': datetime.now().isoformat(),
            'vulnerabilities': [],
            'security_headers': {},
            'ssl_info': {},
            'dns_info': {},
            'subdomain_scan': [],
            'port_scan': [],
            'directory_enumeration': [],
            'vulnerability_tests': {}
        }
        
        try:
            # 1. Basic connectivity and response analysis
            response = self.session.get(url, timeout=10, allow_redirects=True)
            scan_results['status_code'] = response.status_code
            scan_results['final_url'] = response.url
            scan_results['response_headers'] = dict(response.headers)
            
            # 2. Security headers analysis
            scan_results['security_headers'] = self.analyze_security_headers(response.headers)
            
            # 3. SSL/TLS analysis
            if url.startswith('https://'):
                scan_results['ssl_info'] = self.analyze_ssl_certificate(domain)
            
            # 4. DNS analysis
            scan_results['dns_info'] = self.analyze_dns(domain)
            
            # 5. Vulnerability testing
            scan_results['vulnerability_tests'] = self.perform_vulnerability_tests(url, response)
            
            # 6. Directory enumeration
            scan_results['directory_enumeration'] = self.directory_enumeration(base_url)
            
            # 7. Subdomain discovery
            scan_results['subdomain_scan'] = self.subdomain_discovery(domain)
            
            # 8. Port scanning
            scan_results['port_scan'] = self.port_scan(domain)
            
            # 9. Content analysis
            scan_results['content_analysis'] = self.analyze_content(response.text, url)
            
            # 10. Generate vulnerability report
            scan_results['vulnerabilities'] = self.generate_vulnerability_report(scan_results)
            
            print(f"✅ Security scan completed for {url}")
            return scan_results
            
        except Exception as e:
            print(f"❌ Error scanning {url}: {str(e)}")
            scan_results['error'] = str(e)
            return scan_results

    def analyze_security_headers(self, headers):
        """Analyze security headers"""
        security_headers = {
            'Content-Security-Policy': headers.get('Content-Security-Policy', 'Missing'),
            'X-Frame-Options': headers.get('X-Frame-Options', 'Missing'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Missing'),
            'X-XSS-Protection': headers.get('X-XSS-Protection', 'Missing'),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Missing'),
            'Referrer-Policy': headers.get('Referrer-Policy', 'Missing'),
            'Permissions-Policy': headers.get('Permissions-Policy', 'Missing'),
            'Cross-Origin-Embedder-Policy': headers.get('Cross-Origin-Embedder-Policy', 'Missing'),
            'Cross-Origin-Opener-Policy': headers.get('Cross-Origin-Opener-Policy', 'Missing'),
            'Cross-Origin-Resource-Policy': headers.get('Cross-Origin-Resource-Policy', 'Missing')
        }
        
        # Analyze header security
        security_score = 0
        total_headers = len(security_headers)
        
        for header, value in security_headers.items():
            if value != 'Missing':
                security_score += 1
        
        security_headers['security_score'] = round((security_score / total_headers) * 100, 2)
        return security_headers

    def analyze_ssl_certificate(self, domain):
        """Analyze SSL/TLS certificate"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'cipher': ssock.cipher(),
                        'protocol': ssock.version()
                    }
                    
                    # Check certificate validity
                    from datetime import datetime
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    ssl_info['days_until_expiry'] = days_until_expiry
                    ssl_info['is_valid'] = days_until_expiry > 0
                    
                    return ssl_info
        except Exception as e:
            return {'error': str(e)}

    def analyze_dns(self, domain):
        """Analyze DNS records"""
        dns_info = {}
        
        try:
            # A records
            dns_info['A'] = [str(rdata) for rdata in dns.resolver.resolve(domain, 'A')]
        except:
            dns_info['A'] = []
        
        try:
            # AAAA records
            dns_info['AAAA'] = [str(rdata) for rdata in dns.resolver.resolve(domain, 'AAAA')]
        except:
            dns_info['AAAA'] = []
        
        try:
            # MX records
            dns_info['MX'] = [str(rdata) for rdata in dns.resolver.resolve(domain, 'MX')]
        except:
            dns_info['MX'] = []
        
        try:
            # NS records
            dns_info['NS'] = [str(rdata) for rdata in dns.resolver.resolve(domain, 'NS')]
        except:
            dns_info['NS'] = []
        
        try:
            # TXT records
            dns_info['TXT'] = [str(rdata) for rdata in dns.resolver.resolve(domain, 'TXT')]
        except:
            dns_info['TXT'] = []
        
        return dns_info

    def perform_vulnerability_tests(self, url, response):
        """Perform various vulnerability tests"""
        vuln_tests = {
            'sql_injection': self.test_sql_injection(url),
            'xss': self.test_xss_vulnerabilities(url, response),
            'csrf': self.test_csrf_protection(url, response),
            'directory_traversal': self.test_directory_traversal(url),
            'file_upload': self.test_file_upload_vulnerabilities(url),
            'authentication': self.test_authentication_bypass(url),
            'session_management': self.test_session_management(url, response),
            'information_disclosure': self.test_information_disclosure(url, response)
        }
        
        return vuln_tests

    def test_sql_injection(self, url):
        """Test for SQL injection vulnerabilities"""
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL, username, password FROM users--",
            "1' OR '1'='1' --",
            "admin'--",
            "admin' OR '1'='1"
        ]
        
        results = []
        for payload in payloads:
            try:
                # Test in URL parameters
                test_url = f"{url}?id={payload}"
                response = self.session.get(test_url, timeout=5)
                
                if any(keyword in response.text.lower() for keyword in ['error', 'exception', 'sql', 'mysql', 'postgresql', 'oracle']):
                    results.append({
                        'payload': payload,
                        'vulnerable': True,
                        'evidence': 'SQL error detected in response'
                    })
                else:
                    results.append({
                        'payload': payload,
                        'vulnerable': False
                    })
            except:
                continue
        
        vulnerable_payloads = [r for r in results if r.get('vulnerable', False)]
        return {
            'vulnerable': len(vulnerable_payloads) > 0,
            'payloads_tested': len(payloads),
            'vulnerable_payloads': vulnerable_payloads
        }

    def test_xss_vulnerabilities(self, url, response):
        """Test for XSS vulnerabilities"""
        payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "';alert('XSS');//"
        ]
        
        results = []
        for payload in payloads:
            try:
                # Test in URL parameters
                test_url = f"{url}?search={payload}"
                response = self.session.get(test_url, timeout=5)
                
                if payload in response.text:
                    results.append({
                        'payload': payload,
                        'vulnerable': True,
                        'evidence': 'Payload reflected in response'
                    })
                else:
                    results.append({
                        'payload': payload,
                        'vulnerable': False
                    })
            except:
                continue
        
        vulnerable_payloads = [r for r in results if r.get('vulnerable', False)]
        return {
            'vulnerable': len(vulnerable_payloads) > 0,
            'payloads_tested': len(payloads),
            'vulnerable_payloads': vulnerable_payloads
        }

    def test_csrf_protection(self, url, response):
        """Test for CSRF protection"""
        # Check for CSRF tokens in forms
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        csrf_tokens = []
        for form in forms:
            csrf_input = form.find('input', {'name': re.compile(r'csrf|token|_token', re.I)})
            if csrf_input:
                csrf_tokens.append(csrf_input.get('value', ''))
        
        # Check for SameSite cookie attribute
        cookies = response.cookies
        samesite_cookies = []
        for cookie in cookies:
            if hasattr(cookie, 'get') and 'samesite' in str(cookie).lower():
                samesite_cookies.append(str(cookie))
        
        return {
            'csrf_tokens_found': len(csrf_tokens),
            'csrf_tokens': csrf_tokens,
            'samesite_cookies': len(samesite_cookies),
            'protected': len(csrf_tokens) > 0 or len(samesite_cookies) > 0
        }

    def test_directory_traversal(self, url):
        """Test for directory traversal vulnerabilities"""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        results = []
        for payload in payloads:
            try:
                test_url = f"{url}?file={payload}"
                response = self.session.get(test_url, timeout=5)
                
                if any(keyword in response.text.lower() for keyword in ['root:', 'daemon:', 'bin:', 'sys:']):
                    results.append({
                        'payload': payload,
                        'vulnerable': True,
                        'evidence': 'System file content detected'
                    })
                else:
                    results.append({
                        'payload': payload,
                        'vulnerable': False
                    })
            except:
                continue
        
        vulnerable_payloads = [r for r in results if r.get('vulnerable', False)]
        return {
            'vulnerable': len(vulnerable_payloads) > 0,
            'payloads_tested': len(payloads),
            'vulnerable_payloads': vulnerable_payloads
        }

    def test_file_upload_vulnerabilities(self, url):
        """Test for file upload vulnerabilities"""
        # This is a simplified test - in reality, you'd need to find upload endpoints
        return {
            'tested': False,
            'reason': 'Upload endpoints not automatically detected',
            'recommendation': 'Manual testing required for file upload functionality'
        }

    def test_authentication_bypass(self, url):
        """Test for authentication bypass vulnerabilities"""
        # Test common bypass techniques
        bypass_urls = [
            f"{url}/admin",
            f"{url}/admin/",
            f"{url}/admin.php",
            f"{url}/administrator",
            f"{url}/login",
            f"{url}/wp-admin",
            f"{url}/phpmyadmin"
        ]
        
        results = []
        for test_url in bypass_urls:
            try:
                response = self.session.get(test_url, timeout=5)
                if response.status_code == 200 and 'login' not in response.text.lower():
                    results.append({
                        'url': test_url,
                        'accessible': True,
                        'status_code': response.status_code
                    })
            except:
                continue
        
        return {
            'bypass_attempts': len(bypass_urls),
            'accessible_urls': results,
            'vulnerable': len(results) > 0
        }

    def test_session_management(self, url, response):
        """Test session management security"""
        cookies = response.cookies
        session_analysis = {
            'cookies_found': len(cookies),
            'secure_cookies': 0,
            'httponly_cookies': 0,
            'samesite_cookies': 0
        }
        
        for cookie in cookies:
            cookie_str = str(cookie)
            if 'secure' in cookie_str.lower():
                session_analysis['secure_cookies'] += 1
            if 'httponly' in cookie_str.lower():
                session_analysis['httponly_cookies'] += 1
            if 'samesite' in cookie_str.lower():
                session_analysis['samesite_cookies'] += 1
        
        return session_analysis

    def test_information_disclosure(self, url, response):
        """Test for information disclosure"""
        sensitive_patterns = [
            r'password\s*[:=]\s*["\']?[^"\'\s]+["\']?',
            r'api[_-]?key\s*[:=]\s*["\']?[^"\'\s]+["\']?',
            r'secret\s*[:=]\s*["\']?[^"\'\s]+["\']?',
            r'token\s*[:=]\s*["\']?[^"\'\s]+["\']?',
            r'<password>[^<]+</password>',
            r'<api_key>[^<]+</api_key>'
        ]
        
        findings = []
        for pattern in sensitive_patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                findings.extend(matches)
        
        return {
            'sensitive_data_found': len(findings) > 0,
            'findings': findings[:10],  # Limit to first 10 findings
            'total_findings': len(findings)
        }

    def directory_enumeration(self, base_url):
        """Perform directory enumeration"""
        common_dirs = [
            'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin',
            'backup', 'backups', 'config', 'configuration', 'test',
            'dev', 'development', 'staging', 'api', 'docs', 'documentation',
            'files', 'uploads', 'images', 'css', 'js', 'assets'
        ]
        
        results = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for directory in common_dirs:
                future = executor.submit(self.check_directory, base_url, directory)
                futures.append(future)
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
        
        return results

    def check_directory(self, base_url, directory):
        """Check if a directory exists"""
        try:
            url = f"{base_url}/{directory}"
            response = self.session.get(url, timeout=5)
            if response.status_code == 200:
                return {
                    'directory': directory,
                    'url': url,
                    'status_code': response.status_code,
                    'title': BeautifulSoup(response.text, 'html.parser').title.string if BeautifulSoup(response.text, 'html.parser').title else 'No title'
                }
        except:
            pass
        return None

    def subdomain_discovery(self, domain):
        """Discover subdomains"""
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
            'blog', 'shop', 'store', 'app', 'mobile', 'secure', 'vpn',
            'support', 'help', 'docs', 'wiki', 'forum', 'community'
        ]
        
        results = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for subdomain in common_subdomains:
                future = executor.submit(self.check_subdomain, subdomain, domain)
                futures.append(future)
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
        
        return results

    def check_subdomain(self, subdomain, domain):
        """Check if a subdomain exists"""
        try:
            full_domain = f"{subdomain}.{domain}"
            response = self.session.get(f"https://{full_domain}", timeout=5)
            if response.status_code == 200:
                return {
                    'subdomain': subdomain,
                    'domain': full_domain,
                    'status_code': response.status_code,
                    'title': BeautifulSoup(response.text, 'html.parser').title.string if BeautifulSoup(response.text, 'html.parser').title else 'No title'
                }
        except:
            pass
        return None

    def port_scan(self, domain):
        """Perform basic port scan"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306, 1433]
        results = []
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((domain, port))
                if result == 0:
                    results.append({
                        'port': port,
                        'status': 'open',
                        'service': self.get_service_name(port)
                    })
                sock.close()
            except:
                pass
        
        return results

    def get_service_name(self, port):
        """Get service name for port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
            995: 'POP3S', 3389: 'RDP', 5432: 'PostgreSQL', 3306: 'MySQL', 1433: 'MSSQL'
        }
        return services.get(port, 'Unknown')

    def analyze_content(self, content, url):
        """Analyze page content for security issues"""
        soup = BeautifulSoup(content, 'html.parser')
        
        # Find forms
        forms = soup.find_all('form')
        form_analysis = []
        for form in forms:
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            inputs = form.find_all('input')
            form_analysis.append({
                'action': action,
                'method': method,
                'inputs': len(inputs),
                'has_password': any(inp.get('type') == 'password' for inp in inputs)
            })
        
        # Find links
        links = soup.find_all('a', href=True)
        external_links = []
        for link in links:
            href = link['href']
            if href.startswith('http') and urlparse(href).netloc != urlparse(url).netloc:
                external_links.append(href)
        
        # Find scripts
        scripts = soup.find_all('script')
        inline_scripts = [script.string for script in scripts if script.string]
        
        return {
            'forms_found': len(forms),
            'form_analysis': form_analysis,
            'external_links': len(external_links),
            'inline_scripts': len(inline_scripts),
            'total_links': len(links)
        }

    def generate_vulnerability_report(self, scan_results):
        """Generate comprehensive vulnerability report"""
        vulnerabilities = []
        
        # Check security headers
        security_headers = scan_results.get('security_headers', {})
        if security_headers.get('security_score', 0) < 70:
            vulnerabilities.append({
                'type': 'Security Headers',
                'severity': 'Medium',
                'description': f'Insufficient security headers (Score: {security_headers.get("security_score", 0)}%)',
                'recommendation': 'Implement missing security headers like CSP, HSTS, X-Frame-Options, etc.'
            })
        
        # Check SSL certificate
        ssl_info = scan_results.get('ssl_info', {})
        if ssl_info.get('days_until_expiry', 0) < 30:
            vulnerabilities.append({
                'type': 'SSL Certificate',
                'severity': 'High',
                'description': f'SSL certificate expires in {ssl_info.get("days_until_expiry", 0)} days',
                'recommendation': 'Renew SSL certificate before expiration'
            })
        
        # Check vulnerability tests
        vuln_tests = scan_results.get('vulnerability_tests', {})
        
        if vuln_tests.get('sql_injection', {}).get('vulnerable', False):
            vulnerabilities.append({
                'type': 'SQL Injection',
                'severity': 'Critical',
                'description': 'SQL injection vulnerability detected',
                'recommendation': 'Implement parameterized queries and input validation'
            })
        
        if vuln_tests.get('xss', {}).get('vulnerable', False):
            vulnerabilities.append({
                'type': 'Cross-Site Scripting (XSS)',
                'severity': 'High',
                'description': 'XSS vulnerability detected',
                'recommendation': 'Implement proper input sanitization and output encoding'
            })
        
        if not vuln_tests.get('csrf', {}).get('protected', False):
            vulnerabilities.append({
                'type': 'Cross-Site Request Forgery (CSRF)',
                'severity': 'Medium',
                'description': 'No CSRF protection detected',
                'recommendation': 'Implement CSRF tokens and SameSite cookie attributes'
            })
        
        if vuln_tests.get('directory_traversal', {}).get('vulnerable', False):
            vulnerabilities.append({
                'type': 'Directory Traversal',
                'severity': 'High',
                'description': 'Directory traversal vulnerability detected',
                'recommendation': 'Implement proper file path validation and access controls'
            })
        
        if vuln_tests.get('authentication', {}).get('vulnerable', False):
            vulnerabilities.append({
                'type': 'Authentication Bypass',
                'severity': 'Critical',
                'description': 'Authentication bypass vulnerability detected',
                'recommendation': 'Implement proper authentication and authorization controls'
            })
        
        if vuln_tests.get('information_disclosure', {}).get('sensitive_data_found', False):
            vulnerabilities.append({
                'type': 'Information Disclosure',
                'severity': 'Medium',
                'description': 'Sensitive information found in response',
                'recommendation': 'Remove sensitive data from responses and implement proper data handling'
            })
        
        # Check discovered directories
        directories = scan_results.get('directory_enumeration', [])
        if directories:
            vulnerabilities.append({
                'type': 'Directory Enumeration',
                'severity': 'Low',
                'description': f'{len(directories)} sensitive directories discovered',
                'recommendation': 'Review and secure discovered directories'
            })
        
        # Check open ports
        open_ports = scan_results.get('port_scan', [])
        if open_ports:
            vulnerabilities.append({
                'type': 'Open Ports',
                'severity': 'Low',
                'description': f'{len(open_ports)} open ports discovered',
                'recommendation': 'Review and secure open ports'
            })
        
        return vulnerabilities

class AdvancedSecurityScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        self.vulnerabilities = []
        self.scan_results = {}
        
        # Real vulnerability databases and patterns
        self.cve_patterns = self.load_cve_patterns()
        self.owasp_patterns = self.load_owasp_patterns()

    def load_cve_patterns(self):
        """Load CVE vulnerability patterns"""
        return {
            'sql_injection': [
                r"mysql_fetch_array\(\)",
                r"pg_query\(\)",
                r"mssql_query\(\)",
                r"oci_execute\(\)",
                r"sqlite3_exec\(\)"
            ],
            'xss': [
                r"document\.write\(",
                r"innerHTML\s*=",
                r"eval\(",
                r"setTimeout\(",
                r"setInterval\("
            ],
            'command_injection': [
                r"system\(",
                r"exec\(",
                r"shell_exec\(",
                r"passthru\(",
                r"popen\("
            ],
            'path_traversal': [
                r"\.\.\/",
                r"\.\.\\",
                r"\.\.%2f",
                r"\.\.%5c",
                r"\.\.%252f"
            ]
        }

    def load_owasp_patterns(self):
        """Load OWASP Top 10 vulnerability patterns"""
        return {
            'injection': [
                r"union\s+select",
                r"or\s+1\s*=\s*1",
                r"'\s*or\s*'1'\s*=\s*'1",
                r"drop\s+table",
                r"delete\s+from"
            ],
            'broken_authentication': [
                r"password\s*=\s*['\"][^'\"]*['\"]",
                r"admin\s*=\s*['\"][^'\"]*['\"]",
                r"login\s*=\s*['\"][^'\"]*['\"]"
            ],
            'sensitive_data_exposure': [
                r"api[_-]?key\s*[:=]\s*['\"][^'\"]*['\"]",
                r"secret\s*[:=]\s*['\"][^'\"]*['\"]",
                r"token\s*[:=]\s*['\"][^'\"]*['\"]",
                r"password\s*[:=]\s*['\"][^'\"]*['\"]"
            ]
        }

    def comprehensive_web_scan(self, url):
        """Perform comprehensive web application security scan with real techniques"""
        print(f"🔍 Starting advanced security scan for: {url}")
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        scan_results = {
            'url': url,
            'domain': domain,
            'scan_date': datetime.now().isoformat(),
            'vulnerabilities': [],
            'security_headers': {},
            'ssl_info': {},
            'dns_info': {},
            'subdomain_scan': [],
            'port_scan': [],
            'directory_enumeration': [],
            'vulnerability_tests': {},
            'content_analysis': {},
            'network_analysis': {},
            'threat_intelligence': {},
            'exploit_analysis': {}
        }
        
        try:
            # 1. Advanced HTTP Analysis
            response = self.session.get(url, timeout=15, allow_redirects=True, verify=False)
            scan_results['status_code'] = response.status_code
            scan_results['final_url'] = response.url
            scan_results['response_headers'] = dict(response.headers)
            scan_results['response_time'] = response.elapsed.total_seconds()
            
            # 2. Advanced Security Headers Analysis
            scan_results['security_headers'] = self.analyze_security_headers_advanced(response.headers)
            
            # 3. SSL/TLS Deep Analysis
            if url.startswith('https://'):
                scan_results['ssl_info'] = self.analyze_ssl_certificate_advanced(domain)
            
            # 4. DNS Intelligence Gathering
            scan_results['dns_info'] = self.analyze_dns_advanced(domain)
            
            # 5. Advanced Vulnerability Testing
            scan_results['vulnerability_tests'] = self.perform_advanced_vulnerability_tests(url, response)
            
            # 6. Directory and File Enumeration
            scan_results['directory_enumeration'] = self.advanced_directory_enumeration(base_url)
            
            # 7. Subdomain Discovery
            scan_results['subdomain_scan'] = self.advanced_subdomain_discovery(domain)
            
            # 8. Network Port Scanning
            scan_results['port_scan'] = self.advanced_port_scan(domain)
            
            # 9. Content Security Analysis
            scan_results['content_analysis'] = self.analyze_content_advanced(response.text, url)
            
            # 10. Network Analysis
            scan_results['network_analysis'] = self.perform_network_analysis(domain)
            
            # 11. Threat Intelligence
            scan_results['threat_intelligence'] = self.gather_threat_intelligence(domain)
            
            # 12. Exploit Analysis
            scan_results['exploit_analysis'] = self.analyze_exploits(scan_results)
            
            # 13. Generate Advanced Vulnerability Report
            scan_results['vulnerabilities'] = self.generate_advanced_vulnerability_report(scan_results)
            
            print(f"✅ Advanced security scan completed for {url}")
            return scan_results
            
        except Exception as e:
            print(f"❌ Error during advanced scan of {url}: {str(e)}")
            scan_results['error'] = str(e)
            return scan_results

    def analyze_security_headers_advanced(self, headers):
        """Advanced security headers analysis with scoring"""
        security_headers = {
            'Content-Security-Policy': {
                'value': headers.get('Content-Security-Policy', 'Missing'),
                'severity': 'High',
                'description': 'Prevents XSS attacks by controlling resource loading'
            },
            'X-Frame-Options': {
                'value': headers.get('X-Frame-Options', 'Missing'),
                'severity': 'Medium',
                'description': 'Prevents clickjacking attacks'
            },
            'X-Content-Type-Options': {
                'value': headers.get('X-Content-Type-Options', 'Missing'),
                'severity': 'Medium',
                'description': 'Prevents MIME type sniffing'
            },
            'X-XSS-Protection': {
                'value': headers.get('X-XSS-Protection', 'Missing'),
                'severity': 'Low',
                'description': 'Enables XSS filtering in browsers'
            },
            'Strict-Transport-Security': {
                'value': headers.get('Strict-Transport-Security', 'Missing'),
                'severity': 'High',
                'description': 'Forces HTTPS connections'
            }
        }
        
        # Calculate security score
        total_score = 0
        max_score = 0
        
        for header_name, header_info in security_headers.items():
            if header_name == 'security_score':
                continue
                
            max_score += 1
            if header_info['value'] != 'Missing':
                total_score += 1
        
        security_headers['security_score'] = round((total_score / max_score) * 100, 2)
        return security_headers

    def analyze_ssl_certificate_advanced(self, domain):
        """Advanced SSL/TLS certificate analysis"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'cipher': ssock.cipher(),
                        'protocol': ssock.version()
                    }
                    
                    # Check certificate validity
                    from datetime import datetime
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    ssl_info['days_until_expiry'] = days_until_expiry
                    ssl_info['is_valid'] = days_until_expiry > 0
                    
                    return ssl_info
        except Exception as e:
            return {'error': str(e), 'is_valid': False}

    def analyze_dns_advanced(self, domain):
        """Advanced DNS analysis with security checks"""
        dns_info = {}
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                # Set timeout and retry for DNS queries
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 10
                
                dns_info[record_type] = [str(rdata) for rdata in resolver.resolve(domain, record_type)]
                print(f"✅ DNS {record_type} records found: {len(dns_info[record_type])}")
            except dns.resolver.NXDOMAIN:
                dns_info[record_type] = []
                print(f"❌ DNS {record_type}: Domain does not exist")
            except dns.resolver.NoAnswer:
                dns_info[record_type] = []
                print(f"⚠️ DNS {record_type}: No records found")
            except dns.resolver.Timeout:
                dns_info[record_type] = []
                print(f"⏰ DNS {record_type}: Query timeout")
            except Exception as e:
                dns_info[record_type] = []
                print(f"❌ DNS {record_type} error: {str(e)}")
        
        # Add security analysis
        dns_info['security_analysis'] = {
            'has_spf': any('v=spf1' in str(record) for record in dns_info.get('TXT', [])),
            'has_dmarc': any('v=DMARC1' in str(record) for record in dns_info.get('TXT', [])),
            'has_dkim': any('v=DKIM1' in str(record) for record in dns_info.get('TXT', [])),
            'mx_records_count': len(dns_info.get('MX', [])),
            'ns_records_count': len(dns_info.get('NS', [])),
            'total_records': sum(len(records) for records in dns_info.values() if isinstance(records, list))
        }
        
        return dns_info

    def perform_advanced_vulnerability_tests(self, url, response):
        """Perform advanced vulnerability testing with real techniques"""
        vuln_tests = {
            'sql_injection': self.test_sql_injection_advanced(url),
            'xss': self.test_xss_vulnerabilities_advanced(url, response),
            'csrf': self.test_csrf_protection_advanced(url, response),
            'directory_traversal': self.test_directory_traversal_advanced(url),
            'command_injection': self.test_command_injection_advanced(url),
            'information_disclosure': self.test_information_disclosure_advanced(url, response)
        }
        
        return vuln_tests

    def test_sql_injection_advanced(self, url):
        """Advanced SQL injection testing with real payloads"""
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL, username, password FROM users--",
            "1' OR '1'='1' --",
            "admin'--",
            "admin' OR '1'='1"
        ]
        
        results = []
        for payload in payloads:
            try:
                test_url = f"{url}?id={quote(payload)}"
                response = self.session.get(test_url, timeout=10)
                
                error_patterns = [
                    r'mysql_fetch_array\(\)',
                    r'pg_query\(\)',
                    r'mssql_query\(\)',
                    r'oci_execute\(\)',
                    r'sqlite3_exec\(\)',
                    r'SQL syntax',
                    r'mysql error',
                    r'postgresql error'
                ]
                
                error_found = any(re.search(pattern, response.text, re.IGNORECASE) for pattern in error_patterns)
                
                if error_found:
                    results.append({
                        'payload': payload,
                        'vulnerable': True,
                        'evidence': 'SQL error detected in response'
                    })
                else:
                    results.append({
                        'payload': payload,
                        'vulnerable': False
                    })
            except:
                continue
        
        vulnerable_payloads = [r for r in results if r.get('vulnerable', False)]
        return {
            'vulnerable': len(vulnerable_payloads) > 0,
            'payloads_tested': len(payloads),
            'vulnerable_payloads': vulnerable_payloads,
            'severity': 'Critical' if len(vulnerable_payloads) > 0 else 'None'
        }

    def test_xss_vulnerabilities_advanced(self, url, response):
        """Advanced XSS testing with real payloads"""
        payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "';alert('XSS');//"
        ]
        
        results = []
        for payload in payloads:
            try:
                test_url = f"{url}?search={quote(payload)}"
                response = self.session.get(test_url, timeout=10)
                
                if payload in response.text:
                    results.append({
                        'payload': payload,
                        'vulnerable': True,
                        'evidence': 'Payload reflected in response'
                    })
                else:
                    results.append({
                        'payload': payload,
                        'vulnerable': False
                    })
            except:
                continue
        
        vulnerable_payloads = [r for r in results if r.get('vulnerable', False)]
        return {
            'vulnerable': len(vulnerable_payloads) > 0,
            'payloads_tested': len(payloads),
            'vulnerable_payloads': vulnerable_payloads,
            'severity': 'High' if len(vulnerable_payloads) > 0 else 'None'
        }

    def test_csrf_protection_advanced(self, url, response):
        """Advanced CSRF protection testing"""
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        csrf_analysis = {
            'forms_found': len(forms),
            'csrf_tokens': [],
            'samesite_cookies': [],
            'protection_score': 0
        }
        
        # Check for CSRF tokens in forms
        for form in forms:
            csrf_inputs = form.find_all('input', {'name': re.compile(r'csrf|token|_token|authenticity_token', re.I)})
            for csrf_input in csrf_inputs:
                csrf_analysis['csrf_tokens'].append({
                    'name': csrf_input.get('name'),
                    'value': csrf_input.get('value', ''),
                    'type': csrf_input.get('type', 'hidden')
                })
        
        # Check for SameSite cookie attributes
        cookies = response.cookies
        for cookie in cookies:
            cookie_str = str(cookie)
            if 'samesite' in cookie_str.lower():
                csrf_analysis['samesite_cookies'].append(cookie_str)
        
        # Calculate protection score
        score = 0
        if csrf_analysis['csrf_tokens']:
            score += 40
        if csrf_analysis['samesite_cookies']:
            score += 30
        
        csrf_analysis['protection_score'] = min(score, 100)
        csrf_analysis['protected'] = csrf_analysis['protection_score'] >= 50
        
        return csrf_analysis

    def test_directory_traversal_advanced(self, url):
        """Advanced directory traversal testing"""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        results = []
        for payload in payloads:
            try:
                test_url = f"{url}?file={quote(payload)}"
                response = self.session.get(test_url, timeout=10)
                
                system_indicators = [
                    'root:', 'daemon:', 'bin:', 'sys:', 'adm:', 'lp:',
                    'mail:', 'news:', 'uucp:', 'proxy:', 'www-data:'
                ]
                
                if any(indicator in response.text.lower() for indicator in system_indicators):
                    results.append({
                        'payload': payload,
                        'vulnerable': True,
                        'evidence': 'System file content detected',
                        'severity': 'High'
                    })
                else:
                    results.append({
                        'payload': payload,
                        'vulnerable': False
                    })
            except:
                continue
        
        vulnerable_payloads = [r for r in results if r.get('vulnerable', False)]
        return {
            'vulnerable': len(vulnerable_payloads) > 0,
            'payloads_tested': len(payloads),
            'vulnerable_payloads': vulnerable_payloads,
            'severity': 'High' if len(vulnerable_payloads) > 0 else 'None'
        }

    def test_command_injection_advanced(self, url):
        """Advanced command injection testing"""
        payloads = [
            '; ls -la',
            '| whoami',
            '& dir',
            '` id `',
            '$(whoami)'
        ]
        
        results = []
        for payload in payloads:
            try:
                test_url = f"{url}?cmd={quote(payload)}"
                response = self.session.get(test_url, timeout=10)
                
                command_indicators = [
                    'uid=', 'gid=', 'groups=',
                    'total ', 'drwx', '-rw-',
                    'root', 'daemon', 'bin'
                ]
                
                if any(indicator in response.text for indicator in command_indicators):
                    results.append({
                        'payload': payload,
                        'vulnerable': True,
                        'evidence': 'Command output detected',
                        'severity': 'Critical'
                    })
                else:
                    results.append({
                        'payload': payload,
                        'vulnerable': False
                    })
            except:
                continue
        
        vulnerable_payloads = [r for r in results if r.get('vulnerable', False)]
        return {
            'vulnerable': len(vulnerable_payloads) > 0,
            'payloads_tested': len(payloads),
            'vulnerable_payloads': vulnerable_payloads,
            'severity': 'Critical' if len(vulnerable_payloads) > 0 else 'None'
        }

    def test_information_disclosure_advanced(self, url, response):
        """Advanced information disclosure testing"""
        sensitive_patterns = [
            r'api[_-]?key\s*[:=]\s*["\']?[a-zA-Z0-9+/=]{20,}["\']?',
            r'secret\s*[:=]\s*["\']?[a-zA-Z0-9+/=]{20,}["\']?',
            r'token\s*[:=]\s*["\']?[a-zA-Z0-9+/=]{20,}["\']?',
            r'password\s*[:=]\s*["\']?[^"\'\s]{8,}["\']?'
        ]
        
        findings = []
        for pattern in sensitive_patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                findings.extend(matches)
        
        return {
            'sensitive_data_found': len(findings) > 0,
            'findings': findings[:10],
            'total_findings': len(findings),
            'severity': 'High' if len(findings) > 0 else 'None'
        }

    def advanced_directory_enumeration(self, base_url):
        """Advanced directory enumeration with real wordlists"""
        common_dirs = [
            'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin',
            'backup', 'backups', 'config', 'configuration', 'test',
            'dev', 'development', 'staging', 'api', 'docs', 'documentation',
            'files', 'uploads', 'images', 'css', 'js', 'assets'
        ]
        
        results = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for directory in common_dirs:
                future = executor.submit(self.check_directory_advanced, base_url, directory)
                futures.append(future)
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
        
        return results

    def check_directory_advanced(self, base_url, directory):
        """Advanced directory checking with detailed analysis"""
        try:
            url = f"{base_url}/{directory}"
            print(f"🔍 Checking directory: {url}")
            response = self.session.get(url, timeout=5, allow_redirects=True)
            
            if response.status_code in [200, 301, 302, 403, 401]:
                soup = BeautifulSoup(response.text, 'html.parser')
                title = soup.title.string if soup.title else 'No title'
                
                result = {
                    'directory': directory,
                    'url': url,
                    'status_code': response.status_code,
                    'title': title,
                    'severity': 'Medium'
                }
                print(f"✅ Directory found: {url} - {response.status_code}")
                return result
            else:
                print(f"❌ Directory not found: {url} - {response.status_code}")
        except Exception as e:
            print(f"❌ Directory check error for {url}: {str(e)}")
        return None

    def advanced_subdomain_discovery(self, domain):
        """Advanced subdomain discovery with multiple techniques"""
        subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
            'blog', 'shop', 'store', 'app', 'mobile', 'secure', 'vpn',
            'support', 'help', 'docs', 'wiki', 'forum', 'community'
        ]
        
        results = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for subdomain in subdomains:
                future = executor.submit(self.check_subdomain_advanced, subdomain, domain)
                futures.append(future)
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
        
        return results

    def check_subdomain_advanced(self, subdomain, domain):
        """Advanced subdomain checking with detailed analysis"""
        try:
            full_domain = f"{subdomain}.{domain}"
            print(f"🔍 Checking subdomain: {full_domain}")
            
            # First try DNS resolution
            try:
                ip = socket.gethostbyname(full_domain)
                print(f"✅ DNS resolution successful: {full_domain} -> {ip}")
            except:
                print(f"❌ DNS resolution failed: {full_domain}")
                return None
            
            # Then try HTTP/HTTPS
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{full_domain}"
                    response = self.session.get(url, timeout=5, allow_redirects=True)
                    
                    if response.status_code in [200, 301, 302, 403, 401]:
                        soup = BeautifulSoup(response.text, 'html.parser')
                        title = soup.title.string if soup.title else 'No title'
                        
                        result = {
                            'subdomain': subdomain,
                            'domain': full_domain,
                            'protocol': protocol,
                            'status_code': response.status_code,
                            'title': title,
                            'severity': 'Medium'
                        }
                        print(f"✅ Subdomain found: {full_domain} ({protocol}) - {response.status_code}")
                        return result
                except Exception as e:
                    print(f"❌ HTTP check failed for {full_domain} ({protocol}): {str(e)}")
                    continue
        except Exception as e:
            print(f"❌ Subdomain check error for {subdomain}.{domain}: {str(e)}")
        return None

    def advanced_port_scan(self, domain):
        """Advanced port scanning with Nmap"""
        try:
            import nmap
            print(f"🔍 Starting Nmap port scan for {domain}")
            nm = nmap.PortScanner()
            
            # Try to resolve domain to IP first
            try:
                ip = socket.gethostbyname(domain)
                print(f"📍 Resolved {domain} to {ip}")
            except:
                print(f"⚠️ Could not resolve {domain}, using domain directly")
                ip = domain
            
            # Scan common ports with service detection
            nm.scan(ip, '1-1000', arguments='-sS -sV --max-retries 1 --host-timeout 30s')
            
            results = []
            for host in nm.all_hosts():
                print(f"🔍 Scanning host: {host}")
                for port in nm[host].all_tcp():
                    port_info = nm[host]['tcp'][port]
                    result = {
                        'port': port,
                        'state': port_info['state'],
                        'service': port_info['name'],
                        'version': port_info['version'],
                        'severity': 'High' if port in [22, 23, 3389, 5432, 3306, 1433] else 'Medium'
                    }
                    results.append(result)
                    print(f"✅ Port {port} ({port_info['name']}): {port_info['state']}")
            
            print(f"✅ Port scan completed: {len(results)} open ports found")
            return results
        except Exception as e:
            print(f"❌ Nmap scan failed: {str(e)}, falling back to basic scan")
            # Fallback to basic port scanning
            return self.basic_port_scan(domain)

    def basic_port_scan(self, domain):
        """Basic port scanning fallback"""
        print(f"🔍 Starting basic port scan for {domain}")
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306, 1433]
        results = []
        
        # Try to resolve domain to IP first
        try:
            ip = socket.gethostbyname(domain)
            print(f"📍 Resolved {domain} to {ip}")
        except:
            print(f"⚠️ Could not resolve {domain}, using domain directly")
            ip = domain
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    service_name = self.get_service_name(port)
                    result_data = {
                        'port': port,
                        'state': 'open',
                        'service': service_name,
                        'severity': 'High' if port in [22, 23, 3389, 5432, 3306, 1433] else 'Medium'
                    }
                    results.append(result_data)
                    print(f"✅ Port {port} ({service_name}): open")
                sock.close()
            except Exception as e:
                print(f"❌ Port {port}: {str(e)}")
                pass
        
        print(f"✅ Basic port scan completed: {len(results)} open ports found")
        return results

    def get_service_name(self, port):
        """Get service name for port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
            995: 'POP3S', 3389: 'RDP', 5432: 'PostgreSQL', 3306: 'MySQL', 1433: 'MSSQL'
        }
        return services.get(port, 'Unknown')

    def analyze_content_advanced(self, content, url):
        """Advanced content analysis for security issues"""
        soup = BeautifulSoup(content, 'html.parser')
        
        # Form analysis
        forms = soup.find_all('form')
        form_analysis = []
        for form in forms:
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            inputs = form.find_all('input')
            
            form_analysis.append({
                'action': action,
                'method': method,
                'inputs': len(inputs),
                'has_password': any(inp.get('type') == 'password' for inp in inputs)
            })
        
        # Link analysis
        links = soup.find_all('a', href=True)
        external_links = []
        for link in links:
            href = link['href']
            if href.startswith('http') and urlparse(href).netloc != urlparse(url).netloc:
                external_links.append(href)
        
        return {
            'forms_found': len(forms),
            'form_analysis': form_analysis,
            'external_links': len(external_links),
            'total_links': len(links)
        }

    def perform_network_analysis(self, domain):
        """Perform network analysis"""
        try:
            ip = socket.gethostbyname(domain)
            return {
                'ip_address': ip,
                'is_private': ipaddress.ip_address(ip).is_private
            }
        except Exception as e:
            return {'error': str(e)}

    def gather_threat_intelligence(self, domain):
        """Gather threat intelligence information"""
        try:
            domain_info = whois.whois(domain)
            return {
                'domain_info': {
                    'registrar': domain_info.registrar if hasattr(domain_info, 'registrar') else 'Unknown',
                    'creation_date': str(domain_info.creation_date) if hasattr(domain_info, 'creation_date') else 'Unknown'
                }
            }
        except Exception as e:
            return {'error': str(e)}

    def analyze_exploits(self, scan_results):
        """Analyze potential exploits based on scan results"""
        exploits = []
        
        # Check for known vulnerable services
        port_scan = scan_results.get('port_scan', [])
        for port_info in port_scan:
            if port_info.get('severity') == 'High':
                exploits.append({
                    'type': 'Vulnerable Service',
                    'port': port_info.get('port'),
                    'service': port_info.get('service'),
                    'description': f'Vulnerable {port_info.get("service")} service on port {port_info.get("port")}',
                    'severity': 'High'
                })
        
        return {
            'exploits': exploits,
            'total_exploits': len(exploits)
        }

    def generate_advanced_vulnerability_report(self, scan_results):
        """Generate comprehensive vulnerability report"""
        vulnerabilities = []
        
        # Check security headers
        security_headers = scan_results.get('security_headers', {})
        if security_headers.get('security_score', 0) < 70:
            vulnerabilities.append({
                'type': 'Insufficient Security Headers',
                'severity': 'Medium',
                'description': f'Security headers score: {security_headers.get("security_score", 0)}%',
                'recommendation': 'Implement missing security headers',
                'cvss_score': 5.0
            })
        
        # Check SSL certificate
        ssl_info = scan_results.get('ssl_info', {})
        if ssl_info.get('is_expired', False):
            vulnerabilities.append({
                'type': 'Expired SSL Certificate',
                'severity': 'High',
                'description': 'SSL certificate has expired',
                'recommendation': 'Renew SSL certificate immediately',
                'cvss_score': 7.5
            })
        
        # Check vulnerability tests
        vuln_tests = scan_results.get('vulnerability_tests', {})
        
        for vuln_type, test_result in vuln_tests.items():
            if test_result.get('vulnerable', False):
                severity = test_result.get('severity', 'Medium')
                cvss_score = self.get_cvss_score(severity)
                
                vulnerabilities.append({
                    'type': vuln_type.replace('_', ' ').title(),
                    'severity': severity,
                    'description': f'{vuln_type.replace("_", " ").title()} vulnerability detected',
                    'recommendation': self.get_remediation_recommendation(vuln_type),
                    'cvss_score': cvss_score,
                    'evidence': test_result.get('vulnerable_payloads', [])
                })
        
        return vulnerabilities

    def get_cvss_score(self, severity):
        """Get CVSS score based on severity"""
        cvss_scores = {
            'Critical': 9.0,
            'High': 7.0,
            'Medium': 5.0,
            'Low': 3.0,
            'None': 0.0
        }
        return cvss_scores.get(severity, 5.0)

    def get_remediation_recommendation(self, vuln_type):
        """Get remediation recommendation for vulnerability type"""
        recommendations = {
            'sql_injection': 'Implement parameterized queries and input validation',
            'xss': 'Implement proper input sanitization and output encoding',
            'csrf': 'Implement CSRF tokens and SameSite cookie attributes',
            'directory_traversal': 'Implement proper file path validation and access controls',
            'command_injection': 'Implement proper input validation and avoid system commands'
        }
        return recommendations.get(vuln_type, 'Implement proper security controls')

# Example usage
if __name__ == "__main__":
    scanner = SecurityScanner()
    results = scanner.scan_website("https://example.com")
    print(json.dumps(results, indent=2))
