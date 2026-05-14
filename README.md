# ScanPulse-Automated-Detection-and-Security-Assessment-Tool

ScanPulse automates the process of generating a Vulnerability Assessment and Penetration Testing (VAPT) report by parsing Nmap and Nikto scan results and creating a professional PDF report. The tool extracts important details such as open and filtered ports, services, vulnerabilities, and recommendations, and formats them into a well-structured report using the `reportlab` library.

## Key Features

- **Nmap and Nikto Parsing:** Extracts open ports, services, and vulnerabilities.
- **Report Generation:** Creates a PDF report with details such as host information, scan summaries, vulnerability assessment, and recommendations.
- **Customizable:** Easily adaptable to different scan outputs and report formats.

## Usage

Provide the directory containing the Nmap and Nikto scan results, and the script will output a complete PDF report.
