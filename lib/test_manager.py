# -*- coding: utf-8 -*-

from java.util import HashMap, ArrayList
import json
import os
from datetime import datetime
import threading
import time

class TestManager:
    def __init__(self, callbacks):
        self.callbacks = callbacks
        self.test_cases = HashMap()
        self.test_results = HashMap()
        self.active_tests = ArrayList()
        self.test_lock = threading.Lock()
        self.load_test_cases()
    
    def create_test_case(self, name, description, payloads, success_conditions):
        """Create a new test case"""
        test_case = {
            'name': name,
            'description': description,
            'payloads': payloads,
            'success_conditions': success_conditions,
            'created': datetime.now().isoformat(),
            'last_run': None,
            'enabled': True
        }
        
        self.test_cases[name] = test_case
        self.save_test_cases()
        return test_case
    
    def run_test(self, test_name):
        """Run a specific test case"""
        if test_name not in self.test_cases:
            return None
        
        test_case = self.test_cases[test_name]
        if not test_case['enabled']:
            return None
        
        with self.test_lock:
            if test_name in self.active_tests:
                return None
            self.active_tests.add(test_name)
        
        try:
            results = {
                'test_name': test_name,
                'start_time': datetime.now().isoformat(),
                'end_time': None,
                'payloads_tested': 0,
                'successful_payloads': 0,
                'failed_payloads': 0,
                'details': []
            }
            
            for payload in test_case['payloads']:
                payload_result = self.test_payload(payload, test_case['success_conditions'])
                results['payloads_tested'] += 1
                
                if payload_result['success']:
                    results['successful_payloads'] += 1
                else:
                    results['failed_payloads'] += 1
                
                results['details'].append(payload_result)
            
            results['end_time'] = datetime.now().isoformat()
            
            # Store results
            if test_name not in self.test_results:
                self.test_results[test_name] = ArrayList()
            self.test_results[test_name].add(results)
            
            # Update test case
            test_case['last_run'] = results['end_time']
            self.save_test_cases()
            
            return results
            
        finally:
            with self.test_lock:
                self.active_tests.remove(test_name)
    
    def test_payload(self, payload, success_conditions):
        """Test a single payload"""
        result = {
            'payload': payload,
            'timestamp': datetime.now().isoformat(),
            'success': False,
            'response_data': None,
            'matched_conditions': [],
            'failed_conditions': []
        }
        
        try:
            # Send request with payload
            response = self.send_test_request(payload)
            result['response_data'] = self.extract_response_data(response)
            
            # Check success conditions
            all_conditions_met = True
            for condition in success_conditions:
                if self.check_condition(condition, result['response_data']):
                    result['matched_conditions'].append(condition)
                else:
                    result['failed_conditions'].append(condition)
                    all_conditions_met = False
            
            result['success'] = all_conditions_met
            
        except Exception as e:
            result['error'] = str(e)
            result['success'] = False
        
        return result
    
    def send_test_request(self, payload):
        """Send a test request with the payload"""
        # This should be implemented based on your specific needs
        # For now, it's a placeholder
        pass
    
    def extract_response_data(self, response):
        """Extract relevant data from response"""
        if not response:
            return None
            
        return {
            'status_code': response.getStatusCode(),
            'headers': dict(response.getHeaders()),
            'body': response.getResponse()[response.getBodyOffset():].tostring()
        }
    
    def check_condition(self, condition, response_data):
        """Check if a condition is met in the response"""
        if not response_data:
            return False
            
        condition_type = condition.get('type')
        value = condition.get('value')
        
        if condition_type == 'status_code':
            return response_data['status_code'] == value
        
        elif condition_type == 'header_present':
            return value.lower() in [h.lower() for h in response_data['headers']]
        
        elif condition_type == 'header_value':
            header = value.get('header')
            expected = value.get('value')
            return any(h.lower() == header.lower() and v == expected 
                      for h, v in response_data['headers'].items())
        
        elif condition_type == 'body_contains':
            return value in response_data['body']
        
        elif condition_type == 'body_regex':
            import re
            return bool(re.search(value, response_data['body']))
        
        return False
    
    def get_test_results(self, test_name=None):
        """Get test results"""
        if test_name:
            return self.test_results.get(test_name, [])
        return dict(self.test_results)
    
    def get_test_coverage(self):
        """Calculate test coverage statistics"""
        coverage = {
            'total_tests': len(self.test_cases),
            'tests_run': 0,
            'successful_tests': 0,
            'failed_tests': 0,
            'never_run': 0,
            'disabled': 0,
            'coverage_by_type': {}
        }
        
        for test_name, test_case in self.test_cases.items():
            if not test_case['enabled']:
                coverage['disabled'] += 1
                continue
                
            if test_case['last_run'] is None:
                coverage['never_run'] += 1
                continue
            
            coverage['tests_run'] += 1
            
            # Check latest result
            if test_name in self.test_results:
                latest_result = self.test_results[test_name][-1]
                if latest_result['successful_payloads'] > latest_result['failed_payloads']:
                    coverage['successful_tests'] += 1
                else:
                    coverage['failed_tests'] += 1
            
            # Track coverage by payload type
            for payload in test_case['payloads']:
                payload_type = self.detect_payload_type(payload)
                if payload_type not in coverage['coverage_by_type']:
                    coverage['coverage_by_type'][payload_type] = {
                        'total': 0,
                        'tested': 0
                    }
                coverage['coverage_by_type'][payload_type]['total'] += 1
                if test_case['last_run'] is not None:
                    coverage['coverage_by_type'][payload_type]['tested'] += 1
        
        return coverage
    
    def detect_payload_type(self, payload):
        """Detect the type of payload"""
        if '<script' in payload.lower():
            return 'xss'
        elif 'union select' in payload.lower():
            return 'sql_injection'
        elif '../' in payload or '..\\' in payload:
            return 'path_traversal'
        elif '${' in payload or '#{' in payload:
            return 'template_injection'
        return 'other'
    
    def save_test_cases(self):
        """Save test cases to file"""
        try:
            with open('./test_cases.json', 'w') as f:
                json.dump(dict(self.test_cases), f, indent=2)
        except Exception as e:
            print("[!] Error saving test cases: %s" % str(e))
    
    def load_test_cases(self):
        """Load test cases from file"""
        try:
            if os.path.isfile('./test_cases.json'):
                with open('./test_cases.json', 'r') as f:
                    test_cases = json.load(f)
                    for name, case in test_cases.items():
                        self.test_cases[name] = case
        except Exception as e:
            print("[!] Error loading test cases: %s" % str(e))
    
    def save_results(self):
        """Save test results to file"""
        try:
            results_data = {}
            for test_name, results in self.test_results.items():
                results_data[test_name] = list(results)
            
            with open('./test_results.json', 'w') as f:
                json.dump(results_data, f, indent=2)
        except Exception as e:
            print("[!] Error saving test results: %s" % str(e))
    
    def load_results(self):
        """Load test results from file"""
        try:
            if os.path.isfile('./test_results.json'):
                with open('./test_results.json', 'r') as f:
                    results_data = json.load(f)
                    for test_name, results in results_data.items():
                        self.test_results[test_name] = ArrayList(results)
        except Exception as e:
            print("[!] Error loading test results: %s" % str(e)) 