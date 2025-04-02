# Vulnerability Scanner

A comprehensive vulnerability scanner that uses Nmap for port scanning and machine learning for predicting potential vulnerabilities.

## Features

- Scans targets (IP addresses or domain names) using Nmap
- Identifies open ports and running services
- Detects operating system information
- Identifies known vulnerabilities (CVEs) based on detected services
- Uses machine learning to predict potential vulnerabilities
- Determines if exploits exist for detected vulnerabilities
- Generates structured reports in text or JSON format
- Web interface for easy interaction and visualization

## Requirements

- Python 3.7 or higher
- Nmap must be installed on your system (https://nmap.org/download.html)
- Required Python packages (install using `pip install -r requirements.txt`):
  - python-nmap
  - pandas
  - numpy
  - scikit-learn
  - scipy
  - flask

## Installation

1. Clone this repository or download the files
2. Make sure Nmap is installed on your system
3. Install required Python packages:

```bash
pip install -r requirements.txt
```

## Usage

### Command Line Interface

Run the scanner from the command line:

```bash
python vulnerability_scanner.py [target]
```

If you don't provide a target as an argument, you'll be prompted to enter one.

### Web Interface

Run the Flask web application:

```bash
python app.py
```

This will start a local server (usually at http://127.0.0.1:5000). Open this URL in your web browser to access the user-friendly interface where you can:

1. Enter a target IP or domain
2. View scan results with a visual representation
3. See detailed vulnerability information
4. Download reports in JSON or text format

## How It Works

1. **Scanning**: The tool uses Nmap to scan the target for open ports, running services, and OS detection.

2. **Vulnerability Detection**: It compares detected services against a database of known CVEs.

3. **Machine Learning**: For services that don't have direct matches, the tool uses a trained machine learning model to predict potential vulnerabilities.

4. **Exploit Prediction**: The tool also predicts whether exploits exist for detected vulnerabilities.

5. **Report Generation**: Results are presented in a structured format and can be saved as text or JSON files.

## Data

The tool uses a database of CVEs (Common Vulnerabilities and Exposures) stored in `data.csv`. This file contains:

- CVE IDs
- Exploit Database IDs (where available)
- Vulnerability descriptions
- Affected software information

## Screenshots

### Web Interface
The web interface provides an intuitive way to run scans and visualize results:
- Input form for target specification
- Detailed view of open ports and services
- Color-coded vulnerability cards with exploit information
- Tabs for direct matches and ML-predicted vulnerabilities
- One-click report downloads

## License

This project is open source and available under the MIT License. #   m u s k a n P r o j e c t  
 