# -*- coding: utf-8 -*-

from java.awt import Component, FlowLayout, Panel, BorderLayout, Dimension, Color, Toolkit
from java.awt.event import ActionEvent, ActionListener
from javax.swing import (JButton, JLabel, JCheckBox, JTable, JScrollPane, 
                       JTextArea, JTabbedPane, JPanel, BorderFactory, 
                       JTextField, BoxLayout, Box, JFileChooser, JComboBox,
                       JSpinner, SpinnerNumberModel, JOptionPane, JList,
                       DefaultListModel, ListSelectionModel, JSplitPane,
                       SwingUtilities)
from javax.swing.text import DefaultHighlighter
from javax.swing.event import DocumentListener
from java.io import PrintWriter, File, BufferedReader, InputStreamReader
from java.net import URL, HttpURLConnection
from utils import Helpers, PayloadCategory
import json
import csv
import datetime
import os
from java.awt.datatransfer import StringSelection
from java.awt.event import MouseAdapter
import re
import time
import threading
from java.lang.management import ManagementFactory
from java.util import Date, Calendar
from javax.swing import SpinnerDateModel

class GUI(object):
    def __init__(self, burp_extender):
        # Initialize base class
        super(GUI, self).__init__()
        
        self.burp_extender = burp_extender
        self.callbacks = burp_extender.callbacks
        self.helpers = burp_extender.helpers
        
        # Initialize performance monitoring
        self.total_requests = 0
        self.active_requests = 0
        self.max_concurrent_requests = 10
        self.request_delay = 0
        self.max_log_size = 5000
        
        # Main panel
        self.panel = JPanel()
        self.panel.setLayout(BorderLayout())

        # Create tabbed pane
        self.tabbedPane = JTabbedPane()
        
        # Create tabs
        self.scanTab = self.create_scan_tab()
        self.payloadTab = self.create_payload_tab()
        self.logsTab = self.create_logs_tab()
        self.statsTab = self.create_stats_tab()
        self.identifiersTab = self.create_identifiers_tab()
        self.aboutTab = self.create_about_tab()
        
        # Add tabs to pane
        self.tabbedPane.addTab("Scan Settings", self.scanTab)
        self.tabbedPane.addTab("Payload Management", self.payloadTab)
        self.tabbedPane.addTab("Framework Identifiers", self.identifiersTab)
        self.tabbedPane.addTab("Logs", self.logsTab)
        self.tabbedPane.addTab("Statistics", self.statsTab)
        self.tabbedPane.addTab("About", self.aboutTab)
        
        self.panel.add(self.tabbedPane, BorderLayout.CENTER)
        
        # Load settings
        self.load_settings()

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

    def gui(self):
        # Initialize performance monitoring
        self.total_requests = 0
        self.active_requests = 0
        self.max_concurrent_requests = 10
        self.request_delay = 0
        self.max_log_size = 5000
        
        # Main panel
        self.panel = JPanel()
        self.panel.setLayout(BorderLayout())

        # Create tabbed pane
        self.tabbedPane = JTabbedPane()
        
        # Create tabs
        self.scanTab = self.create_scan_tab()
        self.payloadTab = self.create_payload_tab()
        self.logsTab = self.create_logs_tab()
        self.statsTab = self.create_stats_tab()
        self.identifiersTab = self.create_identifiers_tab()
        self.aboutTab = self.create_about_tab()  # New About tab
        
        # Add tabs to pane
        self.tabbedPane.addTab("Scan Settings", self.scanTab)
        self.tabbedPane.addTab("Payload Management", self.payloadTab)
        self.tabbedPane.addTab("Framework Identifiers", self.identifiersTab)
        self.tabbedPane.addTab("Logs", self.logsTab)
        self.tabbedPane.addTab("Statistics", self.statsTab)
        self.tabbedPane.addTab("About", self.aboutTab)
        
        self.panel.add(self.tabbedPane, BorderLayout.CENTER)
        self.load_settings()
        return self

    def create_scan_tab(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        # Scan controls
        controlsPanel = JPanel()
        controlsPanel.setLayout(BoxLayout(controlsPanel, BoxLayout.Y_AXIS))
        controlsPanel.setBorder(BorderFactory.createTitledBorder("Scan Controls"))

        # Basic controls
        basicRow = JPanel(FlowLayout(FlowLayout.LEFT))
        self.enable = JCheckBox("Enable scanning")
        self.randomize = JCheckBox("Randomize payloads")
        basicRow.add(self.enable)
        basicRow.add(self.randomize)

        # Performance controls
        perfRow = JPanel(FlowLayout(FlowLayout.LEFT))
        
        # Concurrent requests control
        perfRow.add(JLabel("Max Concurrent Requests:"))
        self.concurrent_requests = JSpinner(SpinnerNumberModel(10, 1, 50, 1))
        perfRow.add(self.concurrent_requests)
        
        # Request delay control
        perfRow.add(JLabel("Request Delay (ms):"))
        self.request_delay_spinner = JSpinner(SpinnerNumberModel(0, 0, 5000, 100))
        perfRow.add(self.request_delay_spinner)

        # Memory management
        memRow = JPanel(FlowLayout(FlowLayout.LEFT))
        memRow.add(JLabel("Max Log Entries:"))
        self.max_logs_spinner = JSpinner(SpinnerNumberModel(5000, 100, 50000, 1000))
        memRow.add(self.max_logs_spinner)

        controlsPanel.add(basicRow)
        controlsPanel.add(perfRow)
        controlsPanel.add(memRow)
        
        panel.add(controlsPanel)
        panel.add(Box.createVerticalStrut(10))

        return panel

    def create_payload_tab(self):
        panel = JPanel()
        panel.setLayout(BorderLayout())
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        # Left panel for categories
        leftPanel = JPanel(BorderLayout())
        leftPanel.setBorder(BorderFactory.createTitledBorder("Payload Categories"))
        
        # Create category list
        self.category_list_model = DefaultListModel()
        self.category_list = JList(self.category_list_model)
        self.category_list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.category_list.addListSelectionListener(self.category_selected)
        
        # Add default categories
        categories = [
            "Cloudflare Bypass",
            "Laravel",
            "Angular",
            "SSTI",
            "XSS",
            "WAF Bypass",
            "Header Injection",
            "Custom"
        ]
        for category in categories:
            self.category_list_model.addElement(category)
        
        categoryScroll = JScrollPane(self.category_list)
        leftPanel.add(categoryScroll, BorderLayout.CENTER)
        
        # Category buttons
        catButtonPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.add_category_btn = JButton("Add Category", actionPerformed=self.add_category)
        self.remove_category_btn = JButton("Remove Category", actionPerformed=self.remove_category)
        catButtonPanel.add(self.add_category_btn)
        catButtonPanel.add(self.remove_category_btn)
        leftPanel.add(catButtonPanel, BorderLayout.SOUTH)

        # Right panel for payloads
        rightPanel = JPanel(BorderLayout())
        rightPanel.setBorder(BorderFactory.createTitledBorder("Payload Editor"))

        # Import controls panel
        importPanel = JPanel()
        importPanel.setLayout(BoxLayout(importPanel, BoxLayout.Y_AXIS))

        # URL input row
        urlRow = JPanel(FlowLayout(FlowLayout.LEFT))
        urlRow.add(JLabel("URL:"))
        self.url_input = JTextField(40)
        urlRow.add(self.url_input)
        self.fetch_btn = JButton("Fetch from URL", actionPerformed=self.fetch_payloads)
        urlRow.add(self.fetch_btn)

        # Import buttons row
        btnRow = JPanel(FlowLayout(FlowLayout.LEFT))
        self.upload_btn = JButton("Upload File", actionPerformed=self.upload_payloads)
        self.github_btn = JButton("Import from GitHub", actionPerformed=self.import_from_github)
        self.gist_btn = JButton("Import from Gist", actionPerformed=self.import_from_gist)
        btnRow.add(self.upload_btn)
        btnRow.add(self.github_btn)
        btnRow.add(self.gist_btn)

        importPanel.add(urlRow)
        importPanel.add(btnRow)

        # Payload text area
        self.payloads_list = JTextArea()
        self.payloads_list.setLineWrap(True)
        self.payloads_list.setWrapStyleWord(True)
        scrollPane = JScrollPane(self.payloads_list)
        
        # Control buttons
        buttonPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.save_btn = JButton("Save", actionPerformed=self.save_settings)
        self.validate_btn = JButton("Validate Payloads", actionPerformed=self.validate_payloads)
        self.clear_btn = JButton("Clear", actionPerformed=self.clear_payloads)
        buttonPanel.add(self.save_btn)
        buttonPanel.add(self.validate_btn)
        buttonPanel.add(self.clear_btn)

        rightPanel.add(importPanel, BorderLayout.NORTH)
        rightPanel.add(scrollPane, BorderLayout.CENTER)
        rightPanel.add(buttonPanel, BorderLayout.SOUTH)

        # Add detection settings
        detectionPanel = self.create_detection_panel()
        
        # Main layout
        mainPanel = JPanel(BorderLayout())
        mainPanel.add(leftPanel, BorderLayout.WEST)
        mainPanel.add(rightPanel, BorderLayout.CENTER)
        panel.add(mainPanel, BorderLayout.CENTER)
        panel.add(detectionPanel, BorderLayout.SOUTH)

        return panel

    def create_detection_panel(self):
        panel = JPanel()
        panel.setBorder(BorderFactory.createTitledBorder("Framework Detection"))
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))

        # Detection methods
        methodsPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        methodsPanel.add(JLabel("Detection Methods:"))
        self.detect_headers = JCheckBox("Headers", True)
        self.detect_body = JCheckBox("Response Body", True)
        self.detect_errors = JCheckBox("Error Patterns", True)
        methodsPanel.add(self.detect_headers)
        methodsPanel.add(self.detect_body)
        methodsPanel.add(self.detect_errors)

        # Auto-select category
        autoPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.auto_select = JCheckBox("Auto-select payload category based on detection", True)
        autoPanel.add(self.auto_select)

        panel.add(methodsPanel)
        panel.add(autoPanel)
        return panel

    def category_selected(self, event):
        if not event.getValueIsAdjusting():
            selected = self.category_list.getSelectedValue()
            if selected:
                self.load_category_payloads(selected)

    def load_category_payloads(self, category):
        try:
            payloads = PayloadCategory.get_payloads(category)
            self.payloads_list.setText("\n".join(payloads))
            self.log_message("[+] Loaded payloads for category: %s" % category)
        except Exception as e:
            self.log_message("[!] Error loading payloads: %s" % str(e))

    def add_category(self, event):
        name = JOptionPane.showInputDialog(self.panel,
            "Enter new category name:",
            "Add Category",
            JOptionPane.PLAIN_MESSAGE)
        
        if name and name.strip():
            name = name.strip()
            if not self.category_exists(name):
                self.category_list_model.addElement(name)
                self.log_message("[+] Added new category: %s" % name)
            else:
                JOptionPane.showMessageDialog(self.panel,
                    "Category already exists",
                    "Error",
                    JOptionPane.ERROR_MESSAGE)

    def remove_category(self, event):
        selected = self.category_list.getSelectedValue()
        if selected:
            if selected in ["Cloudflare Bypass", "Laravel", "Angular", "SSTI", "XSS", "WAF Bypass"]:
                JOptionPane.showMessageDialog(self.panel,
                    "Cannot remove default category",
                    "Error",
                    JOptionPane.ERROR_MESSAGE)
                return
                
            if JOptionPane.showConfirmDialog(self.panel,
                "Remove category '%s'?" % selected,
                "Confirm Remove",
                JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION:
                self.category_list_model.removeElement(selected)
                self.log_message("[+] Removed category: %s" % selected)

    def category_exists(self, name):
        for i in range(self.category_list_model.getSize()):
            if self.category_list_model.getElementAt(i) == name:
                return True
        return False

    def create_logs_tab(self):
        panel = JPanel()
        panel.setLayout(BorderLayout())
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        # Create split pane for logs and request/response viewer
        splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        # Upper panel for logs
        upperPanel = JPanel(BorderLayout())
        upperPanel.setBorder(BorderFactory.createTitledBorder("Log Messages"))

        # Add filter panel
        filterPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        filterPanel.setBorder(BorderFactory.createTitledBorder("Log Filters"))
        
        # Log level filter
        filterPanel.add(JLabel("Level:"))
        self.log_level_filter = JComboBox(["All", "Info", "Warning", "Error"])
        self.log_level_filter.addActionListener(lambda e: self.apply_filters())
        filterPanel.add(self.log_level_filter)
        
        # Request type filter
        filterPanel.add(JLabel("Type:"))
        self.request_type_filter = JComboBox(["All", "Requests", "Responses", "System"])
        self.request_type_filter.addActionListener(lambda e: self.apply_filters())
        filterPanel.add(self.request_type_filter)
        
        # Time range filter
        filterPanel.add(JLabel("Time:"))
        self.time_filter = JComboBox(["All Time", "Last Hour", "Last 24h", "Custom"])
        self.time_filter.addActionListener(self.time_filter_changed)
        filterPanel.add(self.time_filter)
        
        # Custom time range
        cal = Calendar.getInstance()
        now = cal.getTime()
        cal.add(Calendar.HOUR, -24)  # Default to last 24 hours
        yesterday = cal.getTime()
        
        self.custom_time_start = JSpinner(SpinnerDateModel(yesterday, None, None, Calendar.HOUR))
        self.custom_time_end = JSpinner(SpinnerDateModel(now, None, None, Calendar.HOUR))
        self.custom_time_start.setVisible(False)
        self.custom_time_end.setVisible(False)
        filterPanel.add(self.custom_time_start)
        filterPanel.add(self.custom_time_end)
        
        # Add filter panel to upper panel
        upperPanel.add(filterPanel, BorderLayout.NORTH)

        # Add search panel
        searchPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        searchPanel.add(JLabel("Search:"))
        self.search_field = JTextField(30)
        self.search_field.addActionListener(lambda e: self.search_logs())
        searchPanel.add(self.search_field)
        
        # Search options
        self.case_sensitive = JCheckBox("Case Sensitive")
        self.regex_search = JCheckBox("Regex")
        self.highlight_results = JCheckBox("Highlight Results", True)
        searchPanel.add(self.case_sensitive)
        searchPanel.add(self.regex_search)
        searchPanel.add(self.highlight_results)
        
        # Search buttons
        self.search_prev = JButton("Previous", actionPerformed=lambda e: self.search_logs(forward=False))
        self.search_next = JButton("Next", actionPerformed=lambda e: self.search_logs(forward=True))
        searchPanel.add(self.search_prev)
        searchPanel.add(self.search_next)
        
        upperPanel.add(searchPanel, BorderLayout.NORTH)

        # Create log display area
        self.log_display = JTextArea()
        self.log_display.setEditable(False)
        self.log_display.addMouseListener(LogClickListener(self))
        scrollPane = JScrollPane(self.log_display)
        upperPanel.add(scrollPane, BorderLayout.CENTER)

        # Lower panel for request/response viewer
        lowerPanel = JPanel(BorderLayout())
        lowerPanel.setBorder(BorderFactory.createTitledBorder("Request/Response Viewer"))

        # Create tabbed pane for request and response
        viewerTabs = JTabbedPane()
        
        # Request panel
        requestPanel = JPanel(BorderLayout())
        self.request_viewer = JTextArea()
        self.request_viewer.setEditable(False)
        requestPanel.add(JScrollPane(self.request_viewer), BorderLayout.CENTER)
        
        # Response panel
        responsePanel = JPanel(BorderLayout())
        self.response_viewer = JTextArea()
        self.response_viewer.setEditable(False)
        responsePanel.add(JScrollPane(self.response_viewer), BorderLayout.CENTER)
        
        # Add panels to tabs
        viewerTabs.addTab("Request", requestPanel)
        viewerTabs.addTab("Response", responsePanel)
        
        # Add viewer controls
        viewerControls = JPanel(FlowLayout(FlowLayout.LEFT))
        self.pretty_print = JCheckBox("Pretty Print")
        self.pretty_print.addActionListener(lambda e: self.update_viewers())
        self.wrap_text = JCheckBox("Wrap Text")
        self.wrap_text.addActionListener(lambda e: self.toggle_wrap())
        viewerControls.add(self.pretty_print)
        viewerControls.add(self.wrap_text)
        
        lowerPanel.add(viewerControls, BorderLayout.NORTH)
        lowerPanel.add(viewerTabs, BorderLayout.CENTER)

        # Add panels to split pane
        splitPane.setTopComponent(upperPanel)
        splitPane.setBottomComponent(lowerPanel)
        splitPane.setDividerLocation(300)
        
        # Main panel layout
        panel.add(splitPane, BorderLayout.CENTER)

        # Export controls panel
        exportPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        exportPanel.setBorder(BorderFactory.createTitledBorder("Log Controls"))

        # Format selection
        self.export_format = JComboBox(["CSV", "JSON", "HTML", "TXT"])
        exportPanel.add(JLabel("Export Format:"))
        exportPanel.add(self.export_format)

        # Buttons panel
        self.clear_logs_btn = JButton("Clear Logs", actionPerformed=self.clear_logs)
        self.export_logs_btn = JButton("Export Logs", actionPerformed=self.export_logs)
        self.copy_request_btn = JButton("Copy Request", actionPerformed=self.copy_request)
        self.copy_response_btn = JButton("Copy Response", actionPerformed=self.copy_response)
        
        exportPanel.add(self.clear_logs_btn)
        exportPanel.add(self.export_logs_btn)
        exportPanel.add(self.copy_request_btn)
        exportPanel.add(self.copy_response_btn)

        panel.add(exportPanel, BorderLayout.SOUTH)
        return panel

    def update_viewers(self, request=None, response=None):
        if request is not None:
            if self.pretty_print.isSelected():
                try:
                    # Try to pretty print JSON
                    request_json = json.loads(request)
                    self.request_viewer.setText(json.dumps(request_json, indent=2))
                except:
                    # If not JSON, just show as is
                    self.request_viewer.setText(request)
            else:
                self.request_viewer.setText(request)
                
        if response is not None:
            if self.pretty_print.isSelected():
                try:
                    # Try to pretty print JSON
                    response_json = json.loads(response)
                    self.response_viewer.setText(json.dumps(response_json, indent=2))
                except:
                    # If not JSON, just show as is
                    self.response_viewer.setText(response)
            else:
                self.response_viewer.setText(response)

    def toggle_wrap(self):
        wrap = self.wrap_text.isSelected()
        self.request_viewer.setLineWrap(wrap)
        self.request_viewer.setWrapStyleWord(wrap)
        self.response_viewer.setLineWrap(wrap)
        self.response_viewer.setWrapStyleWord(wrap)

    def copy_request(self, event):
        self.copy_to_clipboard(self.request_viewer.getText())
        self.log_message("[+] Request copied to clipboard")

    def copy_response(self, event):
        self.copy_to_clipboard(self.response_viewer.getText())
        self.log_message("[+] Response copied to clipboard")

    def copy_to_clipboard(self, text):
        toolkit = Toolkit.getDefaultToolkit()
        clipboard = toolkit.getSystemClipboard()
        clipboard.setContents(StringSelection(text), None)

    def create_stats_tab(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        # Statistics display
        statsPanel = JPanel()
        statsPanel.setLayout(BoxLayout(statsPanel, BoxLayout.Y_AXIS))
        statsPanel.setBorder(BorderFactory.createTitledBorder("Performance Statistics"))

        # Create statistics labels
        self.total_requests_label = JLabel("Total Requests: 0")
        self.active_requests_label = JLabel("Active Requests: 0")
        self.memory_usage_label = JLabel("Memory Usage: 0 MB")
        self.cpu_usage_label = JLabel("CPU Usage: 0%")
        self.bandwidth_in_label = JLabel("Network In: 0 KB/s")
        self.bandwidth_out_label = JLabel("Network Out: 0 KB/s")
        
        # Add labels to panel
        statsPanel.add(self.total_requests_label)
        statsPanel.add(Box.createVerticalStrut(5))
        statsPanel.add(self.active_requests_label)
        statsPanel.add(Box.createVerticalStrut(5))
        statsPanel.add(self.memory_usage_label)
        statsPanel.add(Box.createVerticalStrut(5))
        statsPanel.add(self.cpu_usage_label)
        statsPanel.add(Box.createVerticalStrut(5))
        statsPanel.add(self.bandwidth_in_label)
        statsPanel.add(Box.createVerticalStrut(5))
        statsPanel.add(self.bandwidth_out_label)

        # Initialize monitoring
        self.last_update_time = time.time()
        self.last_bytes_in = 0
        self.last_bytes_out = 0
        self.bytes_in = 0
        self.bytes_out = 0
        
        # Start monitoring thread
        self.monitoring_thread = threading.Thread(target=self.monitor_resources)
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()

        panel.add(statsPanel)
        return panel

    def monitor_resources(self):
        """Monitor system resources in a separate thread"""
        while True:
            try:
                self.update_resource_stats()
                time.sleep(1)  # Update every second
            except:
                pass

    def update_resource_stats(self):
        """Update resource statistics"""
        try:
            # Update CPU usage
            cpu_usage = self.get_cpu_usage()
            SwingUtilities.invokeLater(lambda: self.cpu_usage_label.setText("CPU Usage: %.1f%%" % cpu_usage))

            # Update network bandwidth
            current_time = time.time()
            time_diff = current_time - self.last_update_time
            
            # Calculate bandwidth
            bytes_in_diff = self.bytes_in - self.last_bytes_in
            bytes_out_diff = self.bytes_out - self.last_bytes_out
            
            bandwidth_in = bytes_in_diff / time_diff / 1024  # KB/s
            bandwidth_out = bytes_out_diff / time_diff / 1024  # KB/s
            
            SwingUtilities.invokeLater(lambda: self.bandwidth_in_label.setText("Network In: %.1f KB/s" % bandwidth_in))
            SwingUtilities.invokeLater(lambda: self.bandwidth_out_label.setText("Network Out: %.1f KB/s" % bandwidth_out))
            
            # Update last values
            self.last_update_time = current_time
            self.last_bytes_in = self.bytes_in
            self.last_bytes_out = self.bytes_out
            
        except Exception as e:
            print("Error updating resource stats: %s" % str(e))

    def get_cpu_usage(self):
        """Get CPU usage percentage"""
        try:
            # Get process CPU time
            process = ManagementFactory.getRuntimeMXBean()
            cpu_time = ManagementFactory.getThreadMXBean().getCurrentThreadCpuTime()
            
            # Calculate CPU usage
            cpu_count = Runtime.getRuntime().availableProcessors()
            usage = cpu_time / (1000000000.0 * cpu_count)  # Convert to percentage
            
            return min(usage * 100, 100.0)  # Cap at 100%
        except:
            return 0.0

    def update_network_stats(self, request_size, response_size):
        """Update network statistics when a request is made"""
        self.bytes_out += request_size
        self.bytes_in += response_size

    def validate_payloads(self, event):
        payloads = self.get_payloads()
        invalid_payloads = []
        
        for payload in payloads:
            if not payload.strip():  # Skip empty lines
                continue
            if not self.is_valid_payload(payload):
                invalid_payloads.append(payload)
        
        if invalid_payloads:
            self.log_message("Invalid payloads found:")
            for payload in invalid_payloads:
                self.log_message("- %s" % payload)
        else:
            self.log_message("All payloads are valid!")

    def is_valid_payload(self, payload):
        # Basic validation - can be expanded
        return (
            "<script" in payload.lower() and 
            ">" in payload and 
            len(payload.strip()) > 10
        )

    def log_message(self, message):
        if hasattr(self, 'log_display'):
            # Get current log content
            current_text = self.log_display.getText()
            lines = current_text.split("\n")
            
            # Add new log entry
            timestamp = datetime.datetime.now().strftime('%m/%d|%H:%M:%S')
            log_entry = "[%s] %s" % (timestamp, message)
            
            # Trim logs if exceeding max size
            max_logs = int(self.max_logs_spinner.getValue())
            if len(lines) > max_logs:
                lines = lines[len(lines) - max_logs + 1:]
            
            # Update log display
            lines.append(log_entry)
            self.log_display.setText("\n".join(lines))
            
            # Scroll to bottom
            self.log_display.setCaretPosition(self.log_display.getDocument().getLength())

    def clear_logs(self, event):
        self.log_display.setText("")

    def export_logs(self, event):
        # Get log content
        log_content = self.log_display.getText()
        if not log_content.strip():
            self.log_message("[!] No logs to export")
            return

        # Create file chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Save Log File")
        
        # Get selected format
        format_type = self.export_format.getSelectedItem()
        
        # Set file extension based on format
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = "mohra_logs_%s.%s" % (timestamp, format_type.lower())
        chooser.setSelectedFile(File(default_filename))

        # Show save dialog
        if chooser.showSaveDialog(self.panel) == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            
            try:
                # Export based on selected format
                if format_type == "CSV":
                    self.export_csv(file_path, log_content)
                elif format_type == "JSON":
                    self.export_json(file_path, log_content)
                elif format_type == "HTML":
                    self.export_html(file_path, log_content)
                else:  # TXT
                    self.export_txt(file_path, log_content)
                
                self.log_message("[+] Logs exported successfully to: %s" % file_path)
            except Exception as e:
                self.log_message("[!] Error exporting logs: %s" % str(e))

    def export_csv(self, file_path, content):
        # Parse log entries
        entries = []
        for line in content.split("\n"):
            if line.strip():
                # Try to parse timestamp and message
                if "]" in line:
                    timestamp = line[line.find("[")+1:line.find("]")]
                    message = line[line.find("]")+1:].strip()
                else:
                    timestamp = ""
                    message = line
                entries.append([timestamp, message])

        # Write CSV file
        with open(file_path, 'w') as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Message"])
            writer.writerows(entries)

    def export_json(self, file_path, content):
        # Parse log entries
        entries = []
        for line in content.split("\n"):
            if line.strip():
                if "]" in line:
                    timestamp = line[line.find("[")+1:line.find("]")]
                    message = line[line.find("]")+1:].strip()
                else:
                    timestamp = ""
                    message = line
                entries.append({
                    "timestamp": timestamp,
                    "message": message
                })

        # Write JSON file
        with open(file_path, 'w') as f:
            json.dump({"logs": entries}, f, indent=2)

    def export_html(self, file_path, content):
        # Create HTML content
        html_content = """
        <html>
        <head>
            <title>Mohra Logs</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background: #f0f0f0; padding: 10px; }
                .log-entry { border-bottom: 1px solid #eee; padding: 5px; }
                .timestamp { color: #666; }
                .message { margin-left: 10px; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Mohra Logs</h1>
                <p>Generated: %s</p>
            </div>
            <div class="logs">
        """ % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Add log entries
        for line in content.split("\n"):
            if line.strip():
                if "]" in line:
                    timestamp = line[line.find("[")+1:line.find("]")]
                    message = line[line.find("]")+1:].strip()
                    html_content += """
                    <div class="log-entry">
                        <span class="timestamp">[%s]</span>
                        <span class="message">%s</span>
                    </div>
                    """ % (timestamp, message)
                else:
                    html_content += """
                    <div class="log-entry">
                        <span class="message">%s</span>
                    </div>
                    """ % line

        html_content += """
            </div>
        </body>
        </html>
        """

        # Write HTML file
        with open(file_path, 'w') as f:
            f.write(html_content)

    def export_txt(self, file_path, content):
        # Simple text export
        with open(file_path, 'w') as f:
            f.write(content)

    def update_stats(self):
        # Update statistics labels
        self.total_requests_label.setText("Total Requests: %d" % self.total_requests)
        self.active_requests_label.setText("Active Requests: %d" % self.active_requests)
        
        # Calculate memory usage
        runtime = Runtime.getRuntime()
        used_memory = (runtime.totalMemory() - runtime.freeMemory()) / (1024 * 1024)
        self.memory_usage_label.setText("Memory Usage: %.2f MB" % used_memory)

    def get_scan_config(self):
        return {
            'max_concurrent_requests': int(self.concurrent_requests.getValue()),
            'request_delay': int(self.request_delay_spinner.getValue()),
            'max_logs': int(self.max_logs_spinner.getValue())
        }

    def fetch_payloads(self, event):
        url = self.url_input.getText().strip()
        if not url:
            JOptionPane.showMessageDialog(self.panel,
                "Please enter a valid URL",
                "Error",
                JOptionPane.ERROR_MESSAGE)
            return

        try:
            # Create URL connection
            url_obj = URL(url)
            conn = url_obj.openConnection()
            conn.setRequestMethod("GET")
            
            # Read response
            reader = BufferedReader(InputStreamReader(conn.getInputStream()))
            content = []
            line = reader.readLine()
            while line is not None:
                content.append(line)
                line = reader.readLine()
            reader.close()
            
            # Add new payloads to existing ones
            current = self.payloads_list.getText()
            if current and not current.endswith("\n"):
                current += "\n"
            
            self.payloads_list.setText(current + "\n".join(content))
            self.log_message("[+] Successfully imported payloads from URL")
            
        except Exception as e:
            JOptionPane.showMessageDialog(self.panel,
                "Error fetching payloads: %s" % str(e),
                "Error",
                JOptionPane.ERROR_MESSAGE)

    def upload_payloads(self, event):
        chooser = JFileChooser()
        chooser.setDialogTitle("Select Payload File")
        
        if chooser.showOpenDialog(self.panel) == JFileChooser.APPROVE_OPTION:
            try:
                file_path = chooser.getSelectedFile().getAbsolutePath()
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Add new payloads to existing ones
                current = self.payloads_list.getText()
                if current and not current.endswith("\n"):
                    current += "\n"
                
                self.payloads_list.setText(current + content)
                self.log_message("[+] Successfully imported payloads from file")
                
            except Exception as e:
                JOptionPane.showMessageDialog(self.panel,
                    "Error loading file: %s" % str(e),
                    "Error",
                    JOptionPane.ERROR_MESSAGE)

    def import_from_github(self, event):
        url = JOptionPane.showInputDialog(self.panel,
            "Enter GitHub raw file URL:\n" +
            "Example: https://raw.githubusercontent.com/user/repo/branch/file.txt",
            "Import from GitHub",
            JOptionPane.PLAIN_MESSAGE)
            
        if url:
            self.url_input.setText(url)
            self.fetch_payloads(event)

    def import_from_gist(self, event):
        gist_id = JOptionPane.showInputDialog(self.panel,
            "Enter Gist ID or URL:",
            "Import from Gist",
            JOptionPane.PLAIN_MESSAGE)
            
        if gist_id:
            # Extract Gist ID if full URL was provided
            if "/" in gist_id:
                gist_id = gist_id.split("/")[-1]
            
            # Remove any additional parameters or fragments
            gist_id = gist_id.split("?")[0].split("#")[0]
            
            url = "https://gist.githubusercontent.com/raw/" + gist_id
            self.url_input.setText(url)
            self.fetch_payloads(event)

    def clear_payloads(self, event):
        if JOptionPane.showConfirmDialog(self.panel,
            "Are you sure you want to clear all payloads?",
            "Confirm Clear",
            JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION:
            self.payloads_list.setText("")
            self.log_message("[+] Cleared all payloads")

    def create_identifiers_tab(self):
        panel = JPanel()
        panel.setLayout(BorderLayout())
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        # Left panel for framework selection
        leftPanel = JPanel(BorderLayout())
        leftPanel.setBorder(BorderFactory.createTitledBorder("Frameworks"))
        
        # Create framework list
        self.framework_list_model = DefaultListModel()
        self.framework_list = JList(self.framework_list_model)
        self.framework_list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.framework_list.addListSelectionListener(self.framework_selected)
        
        # Add default frameworks
        for framework in PayloadCategory.FRAMEWORK_PATTERNS.keys():
            self.framework_list_model.addElement(framework)
        
        frameworkScroll = JScrollPane(self.framework_list)
        leftPanel.add(frameworkScroll, BorderLayout.CENTER)
        
        # Framework buttons
        frameworkBtnPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.add_framework_btn = JButton("Add Framework", actionPerformed=self.add_framework)
        self.remove_framework_btn = JButton("Remove Framework", actionPerformed=self.remove_framework)
        frameworkBtnPanel.add(self.add_framework_btn)
        frameworkBtnPanel.add(self.remove_framework_btn)
        leftPanel.add(frameworkBtnPanel, BorderLayout.SOUTH)

        # Right panel for pattern editing
        rightPanel = JPanel()
        rightPanel.setLayout(BoxLayout(rightPanel, BoxLayout.Y_AXIS))
        rightPanel.setBorder(BorderFactory.createTitledBorder("Detection Patterns"))

        # Headers panel
        headersPanel = JPanel(BorderLayout())
        headersPanel.setBorder(BorderFactory.createTitledBorder("Headers"))
        self.headers_area = JTextArea(5, 40)
        self.headers_area.setLineWrap(True)
        headersPanel.add(JScrollPane(self.headers_area), BorderLayout.CENTER)

        # Body patterns panel
        bodyPanel = JPanel(BorderLayout())
        bodyPanel.setBorder(BorderFactory.createTitledBorder("Body Patterns"))
        self.body_area = JTextArea(5, 40)
        self.body_area.setLineWrap(True)
        bodyPanel.add(JScrollPane(self.body_area), BorderLayout.CENTER)

        # Error patterns panel
        errorsPanel = JPanel(BorderLayout())
        errorsPanel.setBorder(BorderFactory.createTitledBorder("Error Patterns"))
        self.errors_area = JTextArea(5, 40)
        self.errors_area.setLineWrap(True)
        errorsPanel.add(JScrollPane(self.errors_area), BorderLayout.CENTER)

        # Control buttons
        buttonPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.save_patterns_btn = JButton("Save Patterns", actionPerformed=self.save_patterns)
        self.test_patterns_btn = JButton("Test Patterns", actionPerformed=self.test_patterns)
        buttonPanel.add(self.save_patterns_btn)
        buttonPanel.add(self.test_patterns_btn)

        # Add components to right panel
        rightPanel.add(headersPanel)
        rightPanel.add(Box.createVerticalStrut(10))
        rightPanel.add(bodyPanel)
        rightPanel.add(Box.createVerticalStrut(10))
        rightPanel.add(errorsPanel)
        rightPanel.add(Box.createVerticalStrut(10))
        rightPanel.add(buttonPanel)

        # Main layout
        mainPanel = JPanel(BorderLayout())
        mainPanel.add(leftPanel, BorderLayout.WEST)
        mainPanel.add(rightPanel, BorderLayout.CENTER)
        panel.add(mainPanel)

        return panel

    def framework_selected(self, event):
        if not event.getValueIsAdjusting():
            selected = self.framework_list.getSelectedValue()
            if selected:
                self.load_framework_patterns(selected)

    def load_framework_patterns(self, framework):
        if framework in PayloadCategory.FRAMEWORK_PATTERNS:
            patterns = PayloadCategory.FRAMEWORK_PATTERNS[framework]
            self.headers_area.setText("\n".join(patterns['headers']))
            self.body_area.setText("\n".join(patterns['body']))
            self.errors_area.setText("\n".join(patterns['errors']))
            self.log_message("[+] Loaded patterns for: %s" % framework)

    def save_patterns(self, event):
        selected = self.framework_list.getSelectedValue()
        if not selected:
            JOptionPane.showMessageDialog(self.panel,
                "Please select a framework first",
                "Error",
                JOptionPane.ERROR_MESSAGE)
            return

        try:
            # Update patterns
            PayloadCategory.FRAMEWORK_PATTERNS[selected] = {
                'headers': [h.strip() for h in self.headers_area.getText().split("\n") if h.strip()],
                'body': [b.strip() for b in self.body_area.getText().split("\n") if b.strip()],
                'errors': [e.strip() for e in self.errors_area.getText().split("\n") if e.strip()]
            }
            
            # Save to config file
            self.save_framework_patterns()
            self.log_message("[+] Saved patterns for: %s" % selected)
            
        except Exception as e:
            self.log_message("[!] Error saving patterns: %s" % str(e))

    def save_framework_patterns(self):
        try:
            with open("./framework_patterns.json", "w") as f:
                json.dump(PayloadCategory.FRAMEWORK_PATTERNS, f, indent=2)
        except Exception as e:
            self.log_message("[!] Error saving framework patterns: %s" % str(e))

    def load_framework_patterns_from_file(self):
        try:
            if os.path.isfile('./framework_patterns.json'):
                with open("./framework_patterns.json", "r") as f:
                    patterns = json.loads(f.read())
                PayloadCategory.FRAMEWORK_PATTERNS.update(patterns)
                self.log_message("[+] Loaded framework patterns from file")
        except Exception as e:
            self.log_message("[!] Error loading framework patterns: %s" % str(e))

    def add_framework(self, event):
        name = JOptionPane.showInputDialog(self.panel,
            "Enter new framework name:",
            "Add Framework",
            JOptionPane.PLAIN_MESSAGE)
        
        if name and name.strip():
            name = name.strip()
            if name not in PayloadCategory.FRAMEWORK_PATTERNS:
                PayloadCategory.FRAMEWORK_PATTERNS[name] = {
                    'headers': [],
                    'body': [],
                    'errors': []
                }
                self.framework_list_model.addElement(name)
                self.log_message("[+] Added new framework: %s" % name)
            else:
                JOptionPane.showMessageDialog(self.panel,
                    "Framework already exists",
                    "Error",
                    JOptionPane.ERROR_MESSAGE)

    def remove_framework(self, event):
        selected = self.framework_list.getSelectedValue()
        if selected:
            if selected in ["Cloudflare", "Laravel", "Angular", "WAF"]:
                JOptionPane.showMessageDialog(self.panel,
                    "Cannot remove default framework",
                    "Error",
                    JOptionPane.ERROR_MESSAGE)
                return
                
            if JOptionPane.showConfirmDialog(self.panel,
                "Remove framework '%s'?" % selected,
                "Confirm Remove",
                JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION:
                del PayloadCategory.FRAMEWORK_PATTERNS[selected]
                self.framework_list_model.removeElement(selected)
                self.save_framework_patterns()
                self.log_message("[+] Removed framework: %s" % selected)

    def test_patterns(self, event):
        selected = self.framework_list.getSelectedValue()
        if not selected:
            JOptionPane.showMessageDialog(self.panel,
                "Please select a framework first",
                "Error",
                JOptionPane.ERROR_MESSAGE)
            return

        # Create test dialog
        dialog = JDialog(None, "Test Patterns", True)
        dialog.setLayout(BorderLayout())
        dialog.setSize(600, 400)

        # Create test input areas
        testPanel = JPanel()
        testPanel.setLayout(BoxLayout(testPanel, BoxLayout.Y_AXIS))
        
        # Headers test
        headersPanel = JPanel(BorderLayout())
        headersPanel.setBorder(BorderFactory.createTitledBorder("Test Headers"))
        headersArea = JTextArea(5, 40)
        headersPanel.add(JScrollPane(headersArea), BorderLayout.CENTER)
        
        # Body test
        bodyPanel = JPanel(BorderLayout())
        bodyPanel.setBorder(BorderFactory.createTitledBorder("Test Response Body"))
        bodyArea = JTextArea(5, 40)
        bodyPanel.add(JScrollPane(bodyArea), BorderLayout.CENTER)

        # Test button
        buttonPanel = JPanel()
        testBtn = JButton("Test Detection", actionPerformed=lambda e: self.run_pattern_test(
            selected, headersArea.getText(), bodyArea.getText(), dialog))
        buttonPanel.add(testBtn)

        testPanel.add(headersPanel)
        testPanel.add(Box.createVerticalStrut(10))
        testPanel.add(bodyPanel)
        testPanel.add(Box.createVerticalStrut(10))
        testPanel.add(buttonPanel)

        dialog.add(testPanel)
        dialog.setLocationRelativeTo(self.panel)
        dialog.setVisible(True)

    def run_pattern_test(self, framework, headers, body, dialog):
        try:
            # Parse headers
            header_list = [h.strip() for h in headers.split("\n") if h.strip()]
            
            # Run detection
            detected = PayloadCategory.detect_framework(header_list, body, "")
            
            if framework in detected:
                JOptionPane.showMessageDialog(dialog,
                    "Framework '%s' was successfully detected!" % framework,
                    "Test Result",
                    JOptionPane.INFORMATION_MESSAGE)
            else:
                JOptionPane.showMessageDialog(dialog,
                    "Framework '%s' was not detected.\nDetected frameworks: %s" % (framework, ", ".join(detected) if detected else "none"),
                    "Test Result",
                    JOptionPane.WARNING_MESSAGE)
                
        except Exception as e:
            JOptionPane.showMessageDialog(dialog,
                "Error testing patterns: %s" % str(e),
                "Error",
                JOptionPane.ERROR_MESSAGE)

    def create_about_tab(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20))

        # Title Panel
        titlePanel = JPanel()
        titlePanel.setLayout(BoxLayout(titlePanel, BoxLayout.Y_AXIS))
        titlePanel.setAlignmentX(Component.CENTER_ALIGNMENT)
        
        # Add Mohra title
        titleLabel = JLabel("MOHRA")
        titleLabel.setFont(titleLabel.getFont().deriveFont(24.0))
        titleLabel.setAlignmentX(Component.CENTER_ALIGNMENT)
        
        versionLabel = JLabel("Version 1.0v")
        versionLabel.setAlignmentX(Component.CENTER_ALIGNMENT)
        
        titlePanel.add(titleLabel)
        titlePanel.add(Box.createVerticalStrut(10))
        titlePanel.add(versionLabel)
        titlePanel.add(Box.createVerticalStrut(20))

        # Description Panel
        descPanel = JPanel()
        descPanel.setLayout(BoxLayout(descPanel, BoxLayout.Y_AXIS))
        descPanel.setBorder(BorderFactory.createTitledBorder("About Mohra"))
        
        description = """
Mohra because I love horses, especially Arabian horses.
"""
        
        descLabel = JLabel(description)
        descLabel.setAlignmentX(Component.CENTER_ALIGNMENT)
        descPanel.add(descLabel)

        # Developer Info Panel
        devPanel = JPanel()
        devPanel.setLayout(BoxLayout(devPanel, BoxLayout.Y_AXIS))
        devPanel.setBorder(BorderFactory.createTitledBorder("Developer"))
        
        devInfo = """
Khaled Karimeldin (xElkomy)
"""
        devLabel = JLabel(devInfo)
        devLabel.setAlignmentX(Component.CENTER_ALIGNMENT)
        devPanel.add(devLabel)

        # Add all panels to main panel
        panel.add(titlePanel)
        panel.add(Box.createVerticalStrut(20))
        panel.add(descPanel)
        panel.add(Box.createVerticalStrut(20))
        panel.add(devPanel)

        # Wrap in scroll pane
        scrollPane = JScrollPane(panel)
        scrollPane.setBorder(BorderFactory.createEmptyBorder())
        
        # Create wrapper panel for centering
        wrapperPanel = JPanel(BorderLayout())
        wrapperPanel.add(scrollPane, BorderLayout.CENTER)
        
        return wrapperPanel

    def search_logs(self, forward=True):
        """Search logs for the specified text"""
        try:
            search_text = self.search_field.getText()
            if not search_text:
                return
                
            # Get current caret position
            pos = self.log_display.getCaretPosition()
            text = self.log_display.getText()
            doc = self.log_display.getDocument()
            
            # Prepare search parameters
            if not self.case_sensitive.isSelected():
                text = text.lower()
                search_text = search_text.lower()
                
            # Handle regex search
            if self.regex_search.isSelected():
                try:
                    pattern = re.compile(search_text)
                    matches = list(pattern.finditer(text))
                    if not matches:
                        self.log_message("[!] No matches found")
                        return
                        
                    # Find next/previous match
                    if forward:
                        for match in matches:
                            if match.start() > pos:
                                self.highlight_match(match.start(), match.end())
                                return
                        # Wrap around to first match
                        self.highlight_match(matches[0].start(), matches[0].end())
                    else:
                        for match in reversed(matches):
                            if match.start() < pos:
                                self.highlight_match(match.start(), match.end())
                                return
                        # Wrap around to last match
                        self.highlight_match(matches[-1].start(), matches[-1].end())
                except re.error as e:
                    self.log_message("[!] Invalid regex pattern: %s" % str(e))
                    return
            else:
                # Simple text search
                if forward:
                    next_pos = text.find(search_text, pos)
                    if next_pos == -1:  # Wrap around
                        next_pos = text.find(search_text)
                else:
                    next_pos = text.rfind(search_text, 0, pos)
                    if next_pos == -1:  # Wrap around
                        next_pos = text.rfind(search_text)
                
                if next_pos != -1:
                    self.highlight_match(next_pos, next_pos + len(search_text))
                else:
                    self.log_message("[!] Text not found: %s" % search_text)
                    
        except Exception as e:
            self.log_message("[!] Error during search: %s" % str(e))

    def highlight_match(self, start, end):
        """Highlight the matched text and scroll to it"""
        if self.highlight_results.isSelected():
            # Remove existing highlights
            highlighter = self.log_display.getHighlighter()
            highlighter.removeAllHighlights()
            
            # Add new highlight
            painter = DefaultHighlighter.DefaultHighlightPainter(Color.YELLOW)
            highlighter.addHighlight(start, end, painter)
        
        # Select the text
        self.log_display.setCaretPosition(end)
        self.log_display.moveCaretPosition(start)
        
        # Ensure the selection is visible
        try:
            rect = self.log_display.modelToView(start)
            if rect:
                self.log_display.scrollRectToVisible(rect)
        except:
            pass

    def apply_filters(self):
        """Apply all active filters to the logs"""
        try:
            # Get all log entries
            all_logs = self.get_all_logs()
            filtered_logs = []
            
            # Get filter settings
            level_filter = self.log_level_filter.getSelectedItem()
            type_filter = self.request_type_filter.getSelectedItem()
            time_filter = self.time_filter.getSelectedItem()
            
            for log in all_logs:
                if self.matches_filters(log, level_filter, type_filter, time_filter):
                    filtered_logs.append(log)
            
            # Update display
            self.update_log_display(filtered_logs)
            self.log_message("[+] Applied filters: Level=%s, Type=%s, Time=%s" % 
                (level_filter, type_filter, time_filter))
            
        except Exception as e:
            self.log_message("[!] Error applying filters: %s" % str(e))

    def matches_filters(self, log_entry, level_filter, type_filter, time_filter):
        """Check if log entry matches all active filters"""
        # Level filter
        if level_filter != "All":
            if level_filter == "Info" and not self.is_info_log(log_entry):
                return False
            if level_filter == "Warning" and not self.is_warning_log(log_entry):
                return False
            if level_filter == "Error" and not self.is_error_log(log_entry):
                return False

        # Type filter
        if type_filter != "All":
            if type_filter == "Requests" and not "[Request" in log_entry:
                return False
            if type_filter == "Responses" and not "[Response" in log_entry:
                return False
            if type_filter == "System" and ("[Request" in log_entry or "[Response" in log_entry):
                return False

        # Time filter
        if time_filter != "All Time":
            log_time = self.extract_log_time(log_entry)
            if not log_time:
                return False
                
            now = datetime.datetime.now()
            if time_filter == "Last Hour":
                if (now - log_time).total_seconds() > 3600:
                    return False
            elif time_filter == "Last 24h":
                if (now - log_time).total_seconds() > 86400:
                    return False
            elif time_filter == "Custom":
                start_time = self.custom_time_start.getValue()
                end_time = self.custom_time_end.getValue()
                if log_time < start_time or log_time > end_time:
                    return False

        return True

    def is_info_log(self, log_entry):
        return "[+]" in log_entry or not any(x in log_entry for x in ["[-]", "[!]"])

    def is_warning_log(self, log_entry):
        return "[-]" in log_entry

    def is_error_log(self, log_entry):
        return "[!]" in log_entry

    def extract_log_time(self, log_entry):
        """Extract timestamp from log entry"""
        try:
            if "|" in log_entry:
                time_str = log_entry[log_entry.find("[")+1:log_entry.find("]")]
                return datetime.datetime.strptime(time_str, '%m/%d|%H:%M:%S')
            return None
        except:
            return None

    def get_all_logs(self):
        """Get all log entries as a list"""
        return self.log_display.getText().split("\n")

    def time_filter_changed(self, event):
        """Handle time filter selection change"""
        show_custom = self.time_filter.getSelectedItem() == "Custom"
        self.custom_time_start.setVisible(show_custom)
        self.custom_time_end.setVisible(show_custom)
        self.apply_filters()

class LogClickListener(MouseAdapter):
    def __init__(self, gui):
        self.gui = gui
        
    def mouseClicked(self, event):
        if event.getClickCount() == 2:
            try:
                # Get clicked line
                offset = self.gui.log_display.viewToModel(event.getPoint())
                rowStart = self.gui.log_display.getDocument().getDefaultRootElement().getElementIndex(offset)
                rowEnd = rowStart + 1
                line = self.gui.log_display.getText().split("\n")[rowStart]
                
                # Parse request ID from log line
                if "[Request" in line and "]" in line:
                    request_id = line[line.find("[Request")+8:line.find("]")]
                    self.show_request_details(request_id)
            except Exception as e:
                self.gui.log_message("[!] Error showing request details: %s" % str(e))

    def show_request_details(self, request_id):
        try:
            # Get request details from history
            details = self.gui.callbacks.burpExtender.get_request_details(request_id)
            
            if details:
                request = details['request']
                response = details['response']
                timestamp = details['timestamp']
                
                # Convert request/response to string representation
                request_str = self.format_request(request)
                response_str = self.format_response(response)
                
                # Update viewers
                self.gui.update_viewers(request_str, response_str)
                self.gui.log_message("[+] Loaded details for request %s (Time: %s)" % 
                    (request_id, timestamp.strftime('%H:%M:%S')))
            else:
                self.gui.log_message("[!] Request %s not found in history" % request_id)
        except Exception as e:
            self.gui.log_message("[!] Error loading request details: %s" % str(e))

    def format_request(self, request):
        try:
            # Convert request bytes to string representation
            helpers = self.gui.callbacks.getHelpers()
            requestInfo = helpers.analyzeRequest(request)
            
            # Get headers
            headers = requestInfo.getHeaders()
            
            # Format request
            formatted = "\n".join(headers)
            
            # Add body if present
            body_offset = requestInfo.getBodyOffset()
            if body_offset < len(request):
                body = request[body_offset:].tostring()
                formatted += "\n\n" + body
                
            return formatted
        except:
            return request.tostring()

    def format_response(self, response):
        try:
            # Convert response bytes to string representation
            helpers = self.gui.callbacks.getHelpers()
            responseInfo = helpers.analyzeResponse(response)
            
            # Get headers
            headers = responseInfo.getHeaders()
            
            # Format response
            formatted = "\n".join(headers)
            
            # Add body if present
            body_offset = responseInfo.getBodyOffset()
            if body_offset < len(response):
                body = response[body_offset:].tostring()
                formatted += "\n\n" + body
                
            return formatted
        except:
            return response.tostring()

    def detect_content_type(self, headers):
        """Detect content type from headers"""
        for header in headers:
            if header.lower().startswith("content-type:"):
                content_type = header.split(":", 1)[1].strip().lower()
                if "json" in content_type:
                    return "json"
                elif "xml" in content_type:
                    return "xml"
                elif "html" in content_type:
                    return "html"
        return "text"