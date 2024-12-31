# -*- coding: utf-8 -*-

from burp import IBurpExtender, ITab, IHttpListener
from lib.ui import GUI
from lib.core_manager import CoreManager

class BurpExtender(IBurpExtender, ITab, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("Mohra - Advanced Web Application Testing")
        
        # Initialize core manager
        self.core = CoreManager(callbacks)
        
        # Initialize UI
        self.ui = GUI(self)
        
        # Register UI as tab
        callbacks.addSuiteTab(self)
        
        # Register as HTTP listener
        callbacks.registerHttpListener(self)
        
        # Print banner
        self.print_banner()
        
        # Load saved state
        self.core.load_state()
        
        print("[+] Mohra extension loaded successfully")
    
    def getTabCaption(self):
        return "Mohra"
    
    def getUiComponent(self):
        return self.ui.panel
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            try:
                # Analyze response
                results = self.core.analyze_response(messageInfo)
                
                # Update UI with results
                self.ui.update_analysis_results(results)
                
                # Process any active test cases
                if self.ui.is_scanning_enabled():
                    self.process_test_cases(messageInfo)
            except Exception as e:
                print("[!] Error processing response: %s" % str(e))
    
    def process_test_cases(self, messageInfo):
        """Process active test cases"""
        try:
            # Get current context from analysis
            context = self.core.analyze_response(messageInfo)['contexts']
            
            # Get recommended payloads
            payloads = self.core.get_recommended_payloads(context)
            
            # Create and run test case
            test_case = self.core.create_test_case(
                name="Auto Test - %s" % messageInfo.getUrl().getPath(),
                payloads=payloads,
                context=context
            )
            
            # Run test and track results
            results = self.core.test_manager.run_test(test_case['name'])
            if results:
                for detail in results['details']:
                    self.core.track_payload_result(
                        detail['payload'],
                        context,
                        detail['success']
                    )
        except Exception as e:
            print("[!] Error processing test cases: %s" % str(e))
    
    def print_banner(self):
        banner = """
    __  ___      __
   /  |/  /___  / /_  _________ _
  / /|_/ / __ \/ __ \/ ___/ __ `/
 / /  / / /_/ / / / / /  / /_/ /
/_/  /_/\____/_/ /_/_/   \__,_/

Advanced Web Application Testing Extension
Version: 1.0
Developer: Khaled Karimeldin (xElkomy)
Original Work: Ahmed Ezzat (BitTheByte)
        """
        print(banner)
    
    def extensionUnloaded(self):
        """Save state when extension is unloaded"""
        try:
            self.core.save_state()
            print("[+] Mohra state saved successfully")
        except Exception as e:
            print("[!] Error saving state: %s" % str(e))
