# -*- coding: utf-8 -*-

from java.util import HashMap
from datetime import datetime
from .ml_detector import MLDetector
from .waf_detector import WAFDetector
from .test_manager import TestManager
from .payload_analyzer import PayloadAnalyzer

class CoreManager:
    def __init__(self, callbacks):
        self.callbacks = callbacks
        self.ml_detector = MLDetector()
        self.waf_detector = WAFDetector()
        self.test_manager = TestManager(callbacks)
        self.payload_analyzer = PayloadAnalyzer()
        
        # Shared state
        self.current_framework = None
        self.detected_wafs = []
        self.last_response = None
    
    def analyze_response(self, response_info):
        """Analyze response using all available detectors"""
        self.last_response = response_info
        results = {
            'frameworks': [],
            'wafs': [],
            'contexts': [],
            'timestamp': datetime.now().isoformat()
        }
        
        # Framework detection
        frameworks = self.ml_detector.detect_framework(self.extract_response_data(response_info))
        results['frameworks'] = frameworks
        
        # WAF detection
        wafs = self.waf_detector.detect_waf(response_info)
        results['wafs'] = wafs
        self.detected_wafs = [waf[0] for waf in wafs]
        
        # Context analysis
        contexts = self.payload_analyzer.analyze_context(response_info)
        results['contexts'] = contexts
        
        return results
    
    def process_payload(self, payload, context=None):
        """Process and enhance payload based on current state"""
        processed_payloads = []
        
        # Apply WAF bypasses if WAFs detected
        for waf in self.detected_wafs:
            bypasses = self.waf_detector.suggest_bypass(waf, payload, context)
            processed_payloads.extend(bypasses)
        
        # Generate context-aware mutations
        mutations = self.payload_analyzer.mutate_payload(payload, context)
        processed_payloads.extend(mutations)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_payloads = []
        for p in processed_payloads:
            if p not in seen:
                seen.add(p)
                unique_payloads.append(p)
        
        return unique_payloads
    
    def track_payload_result(self, payload, context, success):
        """Track payload effectiveness"""
        self.payload_analyzer.track_payload(payload, context, success)
        
        # If successful, use as training data for framework detection
        if success and self.current_framework and self.last_response:
            response_data = self.extract_response_data(self.last_response)
            self.ml_detector.train(self.current_framework, response_data, True)
    
    def create_test_case(self, name, payloads, context=None):
        """Create a test case with processed payloads"""
        processed_payloads = []
        for payload in payloads:
            processed = self.process_payload(payload, context)
            processed_payloads.extend(processed)
        
        # Create success conditions based on context
        conditions = self.generate_success_conditions(context)
        
        return self.test_manager.create_test_case(
            name=name,
            description="Auto-generated test case for context: %s" % str(context),
            payloads=processed_payloads,
            success_conditions=conditions
        )
    
    def generate_success_conditions(self, context):
        """Generate appropriate success conditions based on context"""
        conditions = []
        
        if context == 'javascript':
            conditions.extend([
                {'type': 'body_contains', 'value': '<script'},
                {'type': 'body_contains', 'value': '</script>'}
            ])
        elif context == 'html_attribute':
            conditions.extend([
                {'type': 'body_regex', 'value': r'<[^>]+?=([\'"])[^\'"]*\\1'}
            ])
        elif context == 'url':
            conditions.extend([
                {'type': 'body_regex', 'value': r'(?:href|src|action)\s*=\s*[\'"][^\'">]*'}
            ])
        
        # Add general success conditions
        conditions.extend([
            {'type': 'status_code', 'value': 200},
            {'type': 'body_regex', 'value': r'(?i)error|exception|stack trace'}
        ])
        
        return conditions
    
    def extract_response_data(self, response_info):
        """Extract response data in a common format"""
        return {
            'headers': dict(response_info.getHeaders()),
            'body': response_info.getResponse()[response_info.getBodyOffset():].tostring(),
            'status_code': response_info.getStatusCode()
        }
    
    def get_recommended_payloads(self, context=None, limit=5):
        """Get recommended payloads based on effectiveness"""
        return self.payload_analyzer.get_recommended_payloads(context, limit)
    
    def suggest_patterns(self, framework):
        """Get suggested patterns for framework detection"""
        return self.ml_detector.suggest_patterns(framework)
    
    def get_test_coverage(self):
        """Get test coverage statistics"""
        return self.test_manager.get_test_coverage()
    
    def save_state(self):
        """Save state of all components"""
        self.ml_detector.save_training_data()
        self.waf_detector.save_custom_signatures()
        self.test_manager.save_test_cases()
        self.test_manager.save_results()
        self.payload_analyzer.save_stats()
    
    def load_state(self):
        """Load state of all components"""
        self.ml_detector.load_training_data()
        self.waf_detector.load_custom_signatures()
        self.test_manager.load_test_cases()
        self.test_manager.load_results()
        self.payload_analyzer.load_stats() 