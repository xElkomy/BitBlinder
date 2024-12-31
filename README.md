# Mohra - Advanced Web Application Testing Extension

Mohra (مهرة) is an advanced Burp Suite extension for web application testing, focusing on XSS detection and framework fingerprinting. It's a significant enhancement of the original BitBlinder extension, adding numerous features and improvements.

## Features

### Core Features
- Framework Detection System
  - Header-based detection
  - Response body analysis
  - Error pattern matching
  - Custom framework definitions
  - Pattern testing interface

- Advanced Payload Management
  - Categorized payload system
  - Framework-specific payloads
  - Import from URL/GitHub/Gist
  - File upload support
  - Payload validation

- Performance Optimization
  - Concurrent request management
  - Request throttling
  - Memory usage monitoring
  - CPU usage tracking
  - Network bandwidth monitoring
  - Thread pool management

- Comprehensive Logging
  - Real-time logging
  - Advanced filtering (Level, Type, Time)
  - Log export (CSV, JSON, HTML, TXT)
  - Request/Response viewer
  - Search functionality

### User Interface
- Modern tabbed interface
- Real-time statistics
- Framework identifier management
- Payload category management
- Performance monitoring

## Installation

1. Download the latest release
2. In Burp Suite, go to Extender > Extensions
3. Click "Add" and select the downloaded jar file
4. The extension will appear as "Mohra" in the Burp Suite tabs

## Usage

### Basic Configuration
1. Navigate to the "Scan Settings" tab
2. Enable scanning
3. Configure concurrent requests and delays
4. Set memory management options

### Payload Management
1. Use the "Payload Management" tab
2. Select or create payload categories
3. Import payloads from various sources
4. Validate and test payloads

### Framework Detection
1. Use the "Framework Identifiers" tab
2. Configure detection patterns
3. Test patterns against responses
4. Add custom framework definitions

### Logging and Analysis
1. View real-time logs in the "Logs" tab
2. Filter logs by level, type, and time
3. Search through logs with regex support
4. Export logs in various formats

## Upcoming Features
1. Advanced Payload Features
   - Context-aware payload generation
   - Payload mutation engine
   - Success rate tracking

2. Framework Detection Improvements
   - Machine learning detection
   - Pattern suggestions
   - Auto-pattern generation

3. Security Enhancements
   - Input validation
   - Output encoding
   - Custom security rules

## Credits

### Original Author
- Ahmed Ezzat (BitBlinder)
  - GitHub: [Original BitBlinder Repository](https://github.com/BitTheByte/BitBlinder)

### Current Maintainer
- Khaled Karimeldin (xElkomy)
  - GitHub: [https://github.com/xElkomy](https://github.com/xElkomy)

## Version History

### v1.0
- Complete UI overhaul
- Added framework detection system
- Implemented advanced logging
- Added performance monitoring
- Improved payload management
- Added request/response viewer

### v0.05b (Original BitBlinder)
- Basic XSS scanning
- Simple payload management
- Request handling

## License

This project is licensed under the MIT License - see the LICENSE file for details.