# -*- coding: utf-8 -*-

from java.util import HashMap
import re
import random
import json
import os
from datetime import datetime

class PayloadAnalyzer:
    def __init__(self):
        self.payload_stats = HashMap()
        self.mutation_rules = {
            'case_variation': lambda p: [p.lower(), p.upper(), p.title()],
            'encoding_variation': lambda p: [
                p.replace('<', '%3C').replace('>', '%3E'),
                p.replace('<', '&lt;').replace('>', '&gt;'),
                p.replace('<', '\\u003c').replace('>', '\\u003e')
            ],
            'quote_variation': lambda p: [
                p.replace('"', "'"),
                p.replace('"', '`'),
                p.replace('"', '\\"')
            ],
            'space_variation': lambda p: [
                p.replace(' ', '%20'),
                p.replace(' ', '+'),
                p.replace(' ', '/**/')
            ]
        }
        self.load_stats()
    
    def track_payload(self, payload, context, success):
        """Track payload effectiveness"""
        if payload not in self.payload_stats:
            self.payload_stats[payload] = {
                'total_uses': 0,
                'successes': 0,
                'contexts': {},
                'last_used': None,
                'created': datetime.now().isoformat()
            }
        
        stats = self.payload_stats[payload]
        stats['total_uses'] += 1
        if success:
            stats['successes'] += 1
        
        if context not in stats['contexts']:
            stats['contexts'][context] = {
                'uses': 0,
                'successes': 0
            }
        
        context_stats = stats['contexts'][context]
        context_stats['uses'] += 1
        if success:
            context_stats['successes'] += 1
        
        stats['last_used'] = datetime.now().isoformat()
        self.save_stats()
    
    def get_payload_effectiveness(self, payload):
        """Get effectiveness statistics for a payload"""
        if payload in self.payload_stats:
            stats = self.payload_stats[payload]
            success_rate = (stats['successes'] / float(stats['total_uses'])) * 100 if stats['total_uses'] > 0 else 0
            context_rates = {}
            
            for context, context_stats in stats['contexts'].items():
                context_success_rate = (context_stats['successes'] / float(context_stats['uses'])) * 100 if context_stats['uses'] > 0 else 0
                context_rates[context] = context_success_rate
            
            return {
                'success_rate': success_rate,
                'total_uses': stats['total_uses'],
                'context_rates': context_rates,
                'last_used': stats['last_used']
            }
        return None
    
    def mutate_payload(self, payload, context=None):
        """Generate mutations of a payload"""
        mutations = set()
        
        # Apply basic mutations
        for rule_name, rule_func in self.mutation_rules.items():
            mutations.update(rule_func(payload))
        
        # Context-specific mutations
        if context:
            context_mutations = self.get_context_mutations(payload, context)
            mutations.update(context_mutations)
        
        # Remove the original payload and empty mutations
        mutations.discard(payload)
        mutations.discard('')
        
        return list(mutations)
    
    def get_context_mutations(self, payload, context):
        """Generate context-specific mutations"""
        mutations = set()
        
        if context == 'html_attribute':
            mutations.update([
                payload.replace('"', '&quot;'),
                payload.replace("'", '&apos;'),
                payload.replace('<', '&lt;').replace('>', '&gt;')
            ])
        
        elif context == 'javascript':
            mutations.update([
                payload.replace("'", "\\'"),
                payload.replace('"', '\\"'),
                payload.replace('\\', '\\\\')
            ])
        
        elif context == 'url':
            mutations.update([
                payload.replace(' ', '%20'),
                payload.replace('<', '%3C').replace('>', '%3E'),
                payload.replace('"', '%22').replace("'", '%27')
            ])
        
        return mutations
    
    def analyze_context(self, response_info):
        """Analyze response to determine injection context"""
        contexts = []
        response = response_info.getResponse()
        
        # Check headers for reflected content
        headers = response_info.getHeaders()
        for header in headers:
            if 'content-type' in header.lower():
                if 'javascript' in header.lower():
                    contexts.append('javascript')
                elif 'html' in header.lower():
                    contexts.append('html')
                elif 'json' in header.lower():
                    contexts.append('json')
        
        # Check body
        body = response[response_info.getBodyOffset():].tostring()
        
        # Check for JavaScript context
        if re.search(r'<script[^>]*>.*?</script>', body, re.DOTALL):
            contexts.append('javascript')
        
        # Check for HTML attribute context
        if re.search(r'<[^>]+?=([\'"])[^\'"]*\\1', body):
            contexts.append('html_attribute')
        
        # Check for URL context
        if re.search(r'(?:href|src|action)\s*=\s*[\'"][^\'">]*', body):
            contexts.append('url')
        
        return list(set(contexts))
    
    def save_stats(self):
        """Save payload statistics to file"""
        try:
            with open('./payload_stats.json', 'w') as f:
                json.dump(dict(self.payload_stats), f, indent=2)
        except Exception as e:
            print("[!] Error saving payload stats: %s" % str(e))
    
    def load_stats(self):
        """Load payload statistics from file"""
        try:
            if os.path.isfile('./payload_stats.json'):
                with open('./payload_stats.json', 'r') as f:
                    stats = json.load(f)
                    for payload, payload_stats in stats.items():
                        self.payload_stats[payload] = payload_stats
        except Exception as e:
            print("[!] Error loading payload stats: %s" % str(e))
    
    def get_recommended_payloads(self, context=None, limit=5):
        """Get recommended payloads based on effectiveness"""
        all_payloads = []
        
        for payload, stats in self.payload_stats.items():
            success_rate = (stats['successes'] / float(stats['total_uses'])) * 100 if stats['total_uses'] > 0 else 0
            
            if context and context in stats['contexts']:
                context_stats = stats['contexts'][context]
                context_success_rate = (context_stats['successes'] / float(context_stats['uses'])) * 100 if context_stats['uses'] > 0 else 0
                success_rate = (success_rate + context_success_rate) / 2
            
            all_payloads.append((payload, success_rate))
        
        # Sort by success rate and return top N
        all_payloads.sort(key=lambda x: x[1], reverse=True)
        return [p[0] for p in all_payloads[:limit]] 