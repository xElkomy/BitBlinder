# -*- coding: utf-8 -*-

from java.util import HashMap
import re
import json
import os
from datetime import datetime

class WAFDetector:
    def __init__(self):
        self.waf_signatures = {
            'Cloudflare': {
                'headers': [
                    ('server', 'cloudflare'),
                    ('cf-ray', r'.*'),
                    ('cf-cache-status', r'.*')
                ],
                'body_patterns': [
                    r'checking your browser',
                    r'cloudflare ray id',
                    r'performance & security by cloudflare'
                ]
            },
            'ModSecurity': {
                'headers': [
                    ('server', r'.*mod_security.*'),
                    ('x-mod-security', r'.*')
                ],
                'body_patterns': [
                    r'mod_security',
                    r'blocked by mod_security'
                ]
            },
            'AWS WAF': {
                'headers': [
                    ('x-amzn-requestid', r'.*'),
                    ('x-amz-cf-id', r'.*')
                ],
                'body_patterns': [
                    r'aws-waf',
                    r'request blocked by aws waf'
                ]
            },
            'Akamai': {
                'headers': [
                    ('x-akamai-transformed', r'.*'),
                    ('akamai-origin-hop', r'.*')
                ],
                'body_patterns': [
                    r'access denied.*akamai',
                    r'your request has been blocked by akamai'
                ]
            }
        }
        
        self.bypass_techniques = {
            'Cloudflare': [
                self.cloudflare_bypass,
                self.generic_bypass
            ],
            'ModSecurity': [
                self.modsecurity_bypass,
                self.generic_bypass
            ],
            'AWS WAF': [
                self.aws_waf_bypass,
                self.generic_bypass
            ],
            'Akamai': [
                self.akamai_bypass,
                self.generic_bypass
            ]
        }
        
        self.load_custom_signatures()
    
    def detect_waf(self, response_info):
        """Detect WAF presence from response"""
        detected_wafs = []
        headers = dict((h.lower(), v) for h, v in response_info.getHeaders())
        body = response_info.getResponse()[response_info.getBodyOffset():].tostring()
        
        for waf_name, signatures in self.waf_signatures.items():
            confidence = 0
            
            # Check headers
            for header_name, pattern in signatures['headers']:
                if header_name in headers and re.search(pattern, headers[header_name], re.I):
                    confidence += 0.4
            
            # Check body patterns
            for pattern in signatures['body_patterns']:
                if re.search(pattern, body, re.I):
                    confidence += 0.3
            
            if confidence >= 0.5:  # Confidence threshold
                detected_wafs.append((waf_name, confidence))
        
        return detected_wafs
    
    def suggest_bypass(self, waf_name, payload, context=None):
        """Suggest bypass techniques for detected WAF"""
        if waf_name in self.bypass_techniques:
            bypasses = []
            for bypass_func in self.bypass_techniques[waf_name]:
                bypassed_payload = bypass_func(payload, context)
                if bypassed_payload != payload:
                    bypasses.append(bypassed_payload)
            return bypasses
        return []
    
    def cloudflare_bypass(self, payload, context=None):
        """Cloudflare specific bypass techniques"""
        bypasses = []
        
        # URL encoding variations
        bypasses.append(payload.replace('<', '%3C').replace('>', '%3E'))
        
        # Double encoding
        bypasses.append(payload.replace('<', '%253C').replace('>', '%253E'))
        
        # Unicode variations
        bypasses.append(payload.replace('<', '\\u003c').replace('>', '\\u003e'))
        
        # HTML entity encoding
        bypasses.append(payload.replace('<', '&lt;').replace('>', '&gt;'))
        
        return bypasses
    
    def modsecurity_bypass(self, payload, context=None):
        """ModSecurity specific bypass techniques"""
        bypasses = []
        
        # Case variations
        bypasses.append(payload.swapcase())
        
        # Null byte injection
        bypasses.append(payload.replace(' ', '\x00'))
        
        # Comment injection
        bypasses.append(payload.replace(' ', '/**/'))
        
        return bypasses
    
    def aws_waf_bypass(self, payload, context=None):
        """AWS WAF specific bypass techniques"""
        bypasses = []
        
        # Mixed encoding
        bypasses.append(payload.replace('<', '%u003c').replace('>', '%u003e'))
        
        # Overlong UTF-8
        bypasses.append(payload.replace('<', '%c0%bc').replace('>', '%c0%be'))
        
        return bypasses
    
    def akamai_bypass(self, payload, context=None):
        """Akamai specific bypass techniques"""
        bypasses = []
        
        # Tab character replacement
        bypasses.append(payload.replace(' ', '\t'))
        
        # Newline injection
        bypasses.append(payload.replace(' ', '\n'))
        
        return bypasses
    
    def generic_bypass(self, payload, context=None):
        """Generic WAF bypass techniques"""
        bypasses = []
        
        # Basic case variations
        bypasses.append(payload.upper())
        bypasses.append(payload.lower())
        
        # Space alternatives
        bypasses.extend([
            payload.replace(' ', '+'),
            payload.replace(' ', '%20'),
            payload.replace(' ', '\r'),
            payload.replace(' ', '\n'),
            payload.replace(' ', '\t')
        ])
        
        # Quote variations
        if '"' in payload:
            bypasses.extend([
                payload.replace('"', "'"),
                payload.replace('"', '`'),
                payload.replace('"', '%22')
            ])
        
        # Special character encoding
        bypasses.extend([
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('<', '%3C').replace('>', '%3E'),
            payload.replace('<', '&#x3c;').replace('>', '&#x3e;')
        ])
        
        return bypasses
    
    def add_custom_signature(self, name, headers=None, body_patterns=None):
        """Add custom WAF signature"""
        if headers is None:
            headers = []
        if body_patterns is None:
            body_patterns = []
            
        self.waf_signatures[name] = {
            'headers': headers,
            'body_patterns': body_patterns
        }
        self.save_custom_signatures()
    
    def save_custom_signatures(self):
        """Save custom WAF signatures to file"""
        try:
            with open('./waf_signatures.json', 'w') as f:
                json.dump(self.waf_signatures, f, indent=2)
        except Exception as e:
            print("[!] Error saving WAF signatures: %s" % str(e))
    
    def load_custom_signatures(self):
        """Load custom WAF signatures from file"""
        try:
            if os.path.isfile('./waf_signatures.json'):
                with open('./waf_signatures.json', 'r') as f:
                    signatures = json.load(f)
                    self.waf_signatures.update(signatures)
        except Exception as e:
            print("[!] Error loading WAF signatures: %s" % str(e)) 