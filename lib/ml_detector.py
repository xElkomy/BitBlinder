# -*- coding: utf-8 -*-

from java.util import HashMap, ArrayList
import json
import os
from datetime import datetime
import re

class MLDetector:
    def __init__(self):
        self.patterns = HashMap()
        self.training_data = HashMap()
        self.confidence_threshold = 0.75
        self.load_training_data()
    
    def train(self, framework, response_data, is_positive=True):
        """Train the detector with new response data"""
        if framework not in self.training_data:
            self.training_data[framework] = {
                'positive': ArrayList(),
                'negative': ArrayList(),
                'patterns': ArrayList(),
                'last_updated': None
            }
        
        data = self.training_data[framework]
        if is_positive:
            data['positive'].add(response_data)
        else:
            data['negative'].add(response_data)
        
        # Update patterns if we have enough data
        if len(data['positive']) >= 5:
            self.generate_patterns(framework)
        
        data['last_updated'] = datetime.now().isoformat()
        self.save_training_data()
    
    def generate_patterns(self, framework):
        """Generate patterns from training data"""
        data = self.training_data[framework]
        positive_samples = data['positive']
        negative_samples = data['negative']
        
        # Clear existing patterns
        data['patterns'].clear()
        
        # Find common patterns in positive samples
        common_patterns = self.find_common_patterns(positive_samples)
        
        # Filter out patterns that appear in negative samples
        filtered_patterns = []
        for pattern in common_patterns:
            if not self.pattern_in_samples(pattern, negative_samples):
                filtered_patterns.append(pattern)
        
        # Add filtered patterns
        data['patterns'].addAll(filtered_patterns)
        
        # Update detection patterns
        self.patterns[framework] = filtered_patterns
    
    def find_common_patterns(self, samples):
        """Find common patterns in samples"""
        if not samples or len(samples) == 0:
            return []
        
        # Extract potential patterns
        patterns = []
        
        # Headers analysis
        header_patterns = self.analyze_headers(samples)
        patterns.extend(header_patterns)
        
        # Body content analysis
        body_patterns = self.analyze_body_content(samples)
        patterns.extend(body_patterns)
        
        # Error message analysis
        error_patterns = self.analyze_error_messages(samples)
        patterns.extend(error_patterns)
        
        return patterns
    
    def analyze_headers(self, samples):
        """Analyze response headers for patterns"""
        patterns = []
        
        # Collect all headers
        all_headers = {}
        for sample in samples:
            headers = sample.get('headers', {})
            for key, value in headers.items():
                if key not in all_headers:
                    all_headers[key] = []
                all_headers[key].append(value)
        
        # Find consistent header patterns
        for key, values in all_headers.items():
            if len(set(values)) == 1:  # Same value in all samples
                patterns.append(('header', key, values[0]))
            elif len(set(values)) < len(samples) * 0.3:  # Common values
                common_value = max(set(values), key=values.count)
                patterns.append(('header', key, common_value))
        
        return patterns
    
    def analyze_body_content(self, samples):
        """Analyze response body content for patterns"""
        patterns = []
        
        # Collect common strings
        common_strings = self.find_common_strings([s.get('body', '') for s in samples])
        
        # Filter and create patterns
        for string in common_strings:
            if len(string) > 10:  # Ignore very short strings
                patterns.append(('body', 'contains', string))
        
        return patterns
    
    def analyze_error_messages(self, samples):
        """Analyze error messages for patterns"""
        patterns = []
        
        # Collect error messages
        error_messages = []
        for sample in samples:
            body = sample.get('body', '')
            # Look for common error patterns
            errors = re.findall(r'(?i)error[:\s].*?(?:\n|$)', body)
            error_messages.extend(errors)
        
        # Find common error patterns
        if error_messages:
            common_errors = self.find_common_strings(error_messages)
            for error in common_errors:
                patterns.append(('error', 'contains', error))
        
        return patterns
    
    def find_common_strings(self, texts):
        """Find common strings between multiple texts"""
        if not texts:
            return []
        
        # Use longest common substring algorithm for pairs of texts
        common_strings = set()
        for i in range(len(texts)):
            for j in range(i + 1, len(texts)):
                common = self.longest_common_substring(texts[i], texts[j])
                if common and len(common) > 10:  # Minimum length threshold
                    common_strings.add(common)
        
        return list(common_strings)
    
    def longest_common_substring(self, s1, s2):
        """Find the longest common substring between two strings"""
        if not s1 or not s2:
            return ""
        
        m = [[0] * (1 + len(s2)) for _ in range(1 + len(s1))]
        longest, x_longest = 0, 0
        
        for x in range(1, 1 + len(s1)):
            for y in range(1, 1 + len(s2)):
                if s1[x - 1] == s2[y - 1]:
                    m[x][y] = m[x - 1][y - 1] + 1
                    if m[x][y] > longest:
                        longest = m[x][y]
                        x_longest = x
                else:
                    m[x][y] = 0
        
        return s1[x_longest - longest: x_longest]
    
    def detect_framework(self, response_data):
        """Detect framework based on response data"""
        results = {}
        
        for framework, patterns in self.patterns.items():
            confidence = self.calculate_confidence(patterns, response_data)
            if confidence >= self.confidence_threshold:
                results[framework] = confidence
        
        return results
    
    def calculate_confidence(self, patterns, response_data):
        """Calculate confidence score for framework detection"""
        if not patterns:
            return 0.0
        
        matches = 0
        total_patterns = len(patterns)
        
        for pattern_type, key, value in patterns:
            if pattern_type == 'header':
                headers = response_data.get('headers', {})
                if key in headers and headers[key] == value:
                    matches += 1
            elif pattern_type == 'body':
                body = response_data.get('body', '')
                if value in body:
                    matches += 1
            elif pattern_type == 'error':
                body = response_data.get('body', '')
                if value in body:
                    matches += 1
        
        return matches / float(total_patterns)
    
    def suggest_patterns(self, framework):
        """Suggest new patterns based on recent responses"""
        if framework not in self.training_data:
            return []
        
        data = self.training_data[framework]
        positive_samples = data['positive']
        
        # Get recent samples
        recent_samples = positive_samples[-5:] if len(positive_samples) > 5 else positive_samples
        
        # Generate new patterns
        new_patterns = self.find_common_patterns(recent_samples)
        
        # Filter out existing patterns
        existing_patterns = set((p[0], p[1], p[2]) for p in data['patterns'])
        suggested_patterns = [p for p in new_patterns if (p[0], p[1], p[2]) not in existing_patterns]
        
        return suggested_patterns
    
    def save_training_data(self):
        """Save training data to file"""
        try:
            data = {}
            for framework, framework_data in self.training_data.items():
                data[framework] = {
                    'positive': list(framework_data['positive']),
                    'negative': list(framework_data['negative']),
                    'patterns': list(framework_data['patterns']),
                    'last_updated': framework_data['last_updated']
                }
            
            with open('./ml_training_data.json', 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print("[!] Error saving training data: %s" % str(e))
    
    def load_training_data(self):
        """Load training data from file"""
        try:
            if os.path.isfile('./ml_training_data.json'):
                with open('./ml_training_data.json', 'r') as f:
                    data = json.load(f)
                    
                    for framework, framework_data in data.items():
                        self.training_data[framework] = {
                            'positive': ArrayList(framework_data['positive']),
                            'negative': ArrayList(framework_data['negative']),
                            'patterns': ArrayList(framework_data['patterns']),
                            'last_updated': framework_data['last_updated']
                        }
                        
                        # Update patterns
                        self.patterns[framework] = framework_data['patterns']
        except Exception as e:
            print("[!] Error loading training data: %s" % str(e)) 