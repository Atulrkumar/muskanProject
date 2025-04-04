# Advanced Vulnerability Scanner

A comprehensive web-based vulnerability scanning tool that combines network scanning, machine learning-based vulnerability prediction, and detailed reporting capabilities.

## Features

- **Network Scanning**: Uses Nmap for comprehensive network reconnaissance
- **Vulnerability Detection**: Identifies known vulnerabilities and potential security issues
- **Machine Learning Integration**: Predicts potential vulnerabilities using ML models
- **Web Interface**: User-friendly Flask-based web application
- **Detailed Reporting**: Generates both text and JSON reports
- **Real-time Results**: Provides immediate feedback on scan progress
- **Fallback Mechanism**: Includes simulated scanning when Nmap is not available

## Prerequisites

- Python 3.8 or higher
- Nmap (optional but recommended for full functionality)
- Required Python packages (listed in requirements.txt)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd <repository-name>
```

2. Install required Python packages:
```bash
pip install -r requirements.txt
```

3. Install Nmap (recommended for full functionality):
   - Windows: Download and install from [Nmap's official website](https://nmap.org/download.html)
   - Linux: `sudo apt-get install nmap`
   - macOS: `brew install nmap`

## Project Structure

```
├── app.py                 # Main Flask application
├── vulnerability_scanner.py  # Core scanning functionality
├── scan_terminal.py       # Terminal-based scanning interface
├── data.csv              # CVE database
├── requirements.txt      # Python dependencies
├── templates/           # HTML templates
└── scan_results/        # Generated scan reports
```

## Components

### 1. Web Application (app.py)

The Flask web application provides a user-friendly interface for vulnerability scanning:

- **Routes**:
  - `/`: Main page with scan interface
  - `/scan`: Handles scan requests
  - `/download/<filetype>`: Downloads scan reports
  - `/latest-scan`: Retrieves latest scan results

- **Features**:
  - Real-time scan progress updates
  - JSON and text report generation
  - Target validation and cleanup
  - Error handling and fallback mechanisms

### 2. Vulnerability Scanner (vulnerability_scanner.py)

Core scanning functionality that combines network scanning with ML-based vulnerability prediction:

- **Key Functions**:
  - `scan_target()`: Main scanning function
  - `_predict_vulnerabilities()`: ML-based vulnerability prediction
  - `_scan_with_timeout()`: Timeout-protected Nmap scanning
  - `simulate_scan()`: Fallback scanning when Nmap is unavailable

- **ML Model**:
  - Uses RandomForestClassifier
  - Features extracted from CVE descriptions and affected software
  - Predicts exploit probability for potential vulnerabilities

### 3. CVE Database (data.csv)

Contains known vulnerability information used for:
- Direct vulnerability matching
- ML model training
- Vulnerability prediction

## Usage

### Web Interface

1. Start the Flask application:
```bash
python app.py
```

2. Open a web browser and navigate to `http://localhost:5000`

3. Enter a target (IP address or domain) in the input field

4. Click "Scan" to start the vulnerability assessment

5. View results in the web interface or download reports

### Terminal Interface

Run scans directly from the terminal:
```bash
python scan_terminal.py <target>
```

## Scan Process

1. **Target Validation**:
   - Cleans and validates input target
   - Removes http/https prefixes
   - Extracts domain/IP

2. **Network Scanning**:
   - Performs Nmap scan with service detection
   - Identifies open ports and running services
   - Detects OS information when possible

3. **Vulnerability Analysis**:
   - Matches detected services against known vulnerabilities
   - Uses ML model to predict potential vulnerabilities
   - Calculates exploit probabilities

4. **Report Generation**:
   - Creates detailed text report
   - Generates JSON data for web interface
   - Saves results with timestamp

## Output Format

### Text Report
```
Scan Report for <target>
Timestamp: <datetime>

Open Ports:
- Port <number>: <service> <version>

Detected Vulnerabilities:
- CVE-XXXX-XXXX: <description>
  Severity: <level>
  Exploit Probability: <value>
  Affected Software: <software>
```

### JSON Report
```json
{
  "target": "<target>",
  "scan_timestamp": "<datetime>",
  "open_ports": [...],
  "services": [...],
  "cves": [
    {
      "cve_id": "CVE-XXXX-XXXX",
      "description": "...",
      "severity": "...",
      "exploit_probability": 0.XX,
      "affected_software": "..."
    }
  ]
}
```

## Error Handling

The application includes comprehensive error handling:
- Network connectivity issues
- Invalid targets
- Scan timeouts
- Nmap unavailability
- ML model prediction errors

## Security Considerations

- Only scan targets you have permission to test
- Use responsibly and ethically
- Follow local laws and regulations
- Consider network impact of scanning

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Nmap project for network scanning capabilities
- CVE database for vulnerability information
- Scikit-learn for machine learning functionality
- Flask framework for web interface