import streamlit as st
import pandas as pd
import plotly.express as px # type: ignore
import os
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
import glob
import concurrent.futures
import threading
import argparse
from lxml import etree
import json
import numpy as np
from math import pi
import seaborn as sns
import matplotlib.pyplot as plt
import re
import base64
import math
import time
import concurrent.futures
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.lib import colors
from dotenv import load_dotenv
import requests
import ipaddress 
import socket
import logging
from urllib.parse import urlparse

# Create necessary directories
if not os.path.exists("reports"):
    os.makedirs("reports")
if not os.path.exists("scan_results"):
    os.makedirs("scan_results")
if not os.path.exists("ipaddr"):
    os.makedirs("ipaddr")

# Shared thread-safe logging
class ThreadSafeLogger:
    def __init__(self):
        self._lock = threading.Lock()
        self.logs = []

    def log(self, message):
        with self._lock:
            self.logs.append(message)
            st.toast(message)

# Global logger
logger = ThreadSafeLogger()

def is_valid_ip(ip):
    """Validate if input is a proper IPv4 address with octets in range 0-255."""
    ip_pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    
    if not ip_pattern.match(ip):
        return False

    # Ensure each octet is in the valid range (0-255)
    octets = ip.split('.')
    return all(0 <= int(octet) <= 255 for octet in octets)

def resolve_domain(url):
    """Resolve a URL to an IP address by extracting the domain."""
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc if parsed_url.netloc else url  # Extract domain
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return None  # Invalid domain or unreachable host

def resolve_ip_to_domain(ip_address):
    try:
        domain_name = socket.gethostbyaddr(ip_address)[0]
        return domain_name
    except socket.herror:
        return ip_address

def expand_cidr_network(cidr):
    """Expand CIDR notation into a list of IP addresses."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return None  # Invalid CIDR

def is_valid_cidr(cidr):
    """Check if a given string is a valid CIDR notation."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False

def process_targets(networks):
    """Expand CIDR networks and validate individual IPs."""
    valid_ips = []
    
    for target in networks:
        target = target.strip()
        
        if is_valid_cidr(target):
            # Expand CIDR range
            expanded_ips = expand_cidr_network(target)
            if expanded_ips:
                valid_ips.extend(expanded_ips)
        elif is_valid_ip(target):
            valid_ips.append(target)
        else:
            print(f"Invalid target: {target}")
    
    return valid_ips

def run_nmap_scan(network, output_dir):
    # Generate a file name that includes the target IP
    nmap_output = os.path.join(output_dir, f"nmap_output_{network.replace('/', '_').replace('.', '_')}.xml")
    # Updated command using the vulners script to capture CVE data
    nmap_command = f"nmap -sV --script vulners -oX \"{nmap_output}\" {network}"
    try:
        result = subprocess.run(nmap_command, shell=True, check=True, capture_output=True, text=True)
        logger.log(f"Nmap scan (with vulners) completed for {network}")
        return nmap_output
    except subprocess.CalledProcessError as e:
        logger.log(f"Error running Nmap for {network}: {str(e)}")
        return None

def run_nmap_scan1(network, output_dir):
    # Generate a file name that includes the target IP
    nmap_output = os.path.join(output_dir, f"nmap_output_{network.replace('/', '_').replace('.', '_')}.xml")
    nmap_command = f"nmap -sV -oX \"{nmap_output}\" {network}"
    try:
        result = subprocess.run(nmap_command, shell=True, check=True, capture_output=True, text=True)
        logger.log(f"Nmap scan completed for {network}")
        return nmap_output
    except subprocess.CalledProcessError as e:
        logger.log(f"Error running Nmap for {network}: {str(e)}")
        return None

def run_nikto_scan(ip_address, output_dir):
    # Generate a file name that includes the target IP
    nikto_output = os.path.join(output_dir, f"nikto_output_{ip_address.replace('.', '_')}.xml")
    nikto_command = f"nikto -h http://{ip_address} -o \"{nikto_output}\" -Format xml"
    try:
        result = subprocess.run(nikto_command, shell=True, check=True, capture_output=True, text=True)
        logger.log(f"Nikto scan completed for {ip_address}")
        return nikto_output
    except subprocess.CalledProcessError as e:
        logger.log(f"Error running Nikto for {ip_address}: {str(e)}")
        return None



# Function to run Nikto scan
def run_nikto_scan1(ip_address, output_dir):
    #nikto_output = os.path.join(output_dir, f"nikto_output_{ip_address.replace('.', '_')}.xml")

    nikto_output = os.path.join(output_dir, f"nikto_output.xml")
    nikto_command = f"nikto -h http://{ip_address} -o \"{nikto_output}\" -Format xml"
    try:
        result = subprocess.run(nikto_command, shell=True, check=True, capture_output=True, text=True)
        logger.log(f"Nikto scan completed for {ip_address}")
        return nikto_output
    except subprocess.CalledProcessError as e:
        logger.log(f"Error running Nikto for {ip_address}: {str(e)}")
        return None

def save_ip_details(target_ip, open_ports, filtered_ports, nikto_findings, cvss_data_dict):
    """
    Save IP details to a JSON file in the ipaddr directory with consistent formatting.
    This version also saves CVSS data including:
      - Total vulnerabilities found
      - Level-wise vulnerability counts
      - An overall vulnerability level
    """
    # Process Nikto findings for web vulnerabilities
    if nikto_findings:
        vulnerabilities = [str(finding) for finding in nikto_findings if finding]  # Ensure all findings are captured
    else:
        vulnerabilities = []

    # Calculate CVSS metrics based on cvss_data_dict
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for info in cvss_data_dict.values():
        if info is not None:
            sev = info.get("baseSeverity", "INFO").upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts[sev] = 1
        else:
            severity_counts["INFO"] += 1
    total_vulnerabilities = sum(severity_counts.values())
    
    # Compute overall vulnerability level: highest severity found
    overall_level = "None"
    if total_vulnerabilities > 0:
        if severity_counts["CRITICAL"] > 0:
            overall_level = "CRITICAL"
        elif severity_counts["HIGH"] > 0:
            overall_level = "HIGH"
        elif severity_counts["MEDIUM"] > 0:
            overall_level = "MEDIUM"
        elif severity_counts["LOW"] > 0:
            overall_level = "LOW"
        else:
            overall_level = "INFO"

    ip_data = {
        "timestamp": datetime.now().isoformat(),  # ISO 8601 format
        "ip_address": str(target_ip),
        "open_ports": [
            {"port": str(port), "service": str(service)} 
            for port, service in open_ports
        ],
        "filtered_ports": [
            {"port": str(port), "service": str(service)} 
            for port, service in filtered_ports
        ],
        "web_vulnerabilities": [str(finding) for finding in vulnerabilities if finding],
        "cvss_data": {
            "total_vulnerabilities": total_vulnerabilities,
            "severity_counts": severity_counts,
            "overall_vulnerability_level": overall_level
        }
    }

    base_filename = os.path.join("ipaddr", f"{target_ip.replace('.', '_')}_details.json")
    
    try:
        if os.path.exists(base_filename):
            with open(base_filename, 'r') as f:
                try:
                    existing_data = json.load(f)
                    if not isinstance(existing_data, list):
                        existing_data = [existing_data]
                except json.JSONDecodeError:
                    existing_data = []
        else:
            existing_data = []
    
        existing_data.append(ip_data)
        
        with open(base_filename, 'w') as f:
            json.dump(existing_data, f, indent=4)
    
    except IOError as e:
        st.error(f"Error saving IP details: {e}")


def save_ip_details1(target_ip, open_ports, filtered_ports, nikto_findings):
    """
    Save IP details to a JSON file in the ipaddr directory with consistent formatting.
    """
    # Ensure vulnerabilities are stored as full strings.
    # If nikto_findings is empty, use an empty list; otherwise, process the first element.
    if nikto_findings:
        vulnerabilities = nikto_findings[0]
        if isinstance(vulnerabilities, str):
            vulnerabilities = [vulnerabilities]
    else:
        vulnerabilities = []

    ip_data = {
        "timestamp": datetime.now().isoformat(),  # Ensure ISO 8601 format
        "ip_address": str(target_ip),
        "open_ports": [
            {"port": str(port), "service": str(service)} 
            for port, service in open_ports
        ],
        "filtered_ports": [
            {"port": str(port), "service": str(service)} 
            for port, service in filtered_ports
        ],
        "web_vulnerabilities": [str(finding) for finding in vulnerabilities if finding]
    }

    base_filename = os.path.join("ipaddr", f"{target_ip.replace('.', '_')}_details.json")
    
    try:
        if os.path.exists(base_filename):
            with open(base_filename, 'r') as f:
                try:
                    existing_data = json.load(f)
                    if not isinstance(existing_data, list):
                        existing_data = [existing_data]
                except json.JSONDecodeError:
                    existing_data = []
        else:
            existing_data = []
    
        existing_data.append(ip_data)
        
        with open(base_filename, 'w') as f:
            json.dump(existing_data, f, indent=4)
    
    except IOError as e:
        st.error(f"Error saving IP details: {e}")


def get_all_ip_scan_details():
    """
    Retrieve the most recent scan details for all IP addresses with error handling.
    
    Returns:
        list: Most recent scan details for each IP address, including CVSS data.
    """
    ip_details = []
    
    # Check if ipaddr directory exists
    if not os.path.exists("ipaddr"):
        st.warning("IP address details directory not found.")
        return ip_details

    # Check if directory is empty
    ip_files = [f for f in os.listdir("ipaddr") if f.endswith("_details.json")]
    
    if not ip_files:
        st.info("No IP scan details found. Run a scan to generate details.")
        return ip_details

    # Process each JSON file
    for filename in ip_files:
        filepath = os.path.join("ipaddr", filename)
        try:
            with open(filepath, 'r') as f:
                file_content = f.read().strip()
                
                # Check if file is empty
                if not file_content:
                    st.warning(f"Empty file found: {filename}")
                    continue
                
                # Attempt to parse JSON
                try:
                    all_ip_data = json.loads(file_content)
                    
                    # Get the most recent scan (last item in the list)
                    if all_ip_data and isinstance(all_ip_data, list):
                        latest_ip_data = all_ip_data[-1]
                        
                        # If cvss_data key is missing, add a default structure
                        if "cvss_data" not in latest_ip_data:
                            latest_ip_data["cvss_data"] = {
                                "total_vulnerabilities": 0,
                                "severity_counts": {
                                    "CRITICAL": 0,
                                    "HIGH": 0,
                                    "MEDIUM": 0,
                                    "LOW": 0,
                                    "INFO": 0
                                },
                                "overall_vulnerability_level": "N/A"
                            }
                        
                        # Validate the structure of the JSON
                        required_keys = ['ip_address', 'open_ports', 'filtered_ports', 'web_vulnerabilities', 'cvss_data']
                        if all(key in latest_ip_data for key in required_keys):
                            ip_details.append(latest_ip_data)
                        else:
                            st.warning(f"Incomplete data in file: {filename}")
                
                except json.JSONDecodeError:
                    st.error(f"JSON decoding error in file: {filename}")
        
        except IOError as e:
            st.error(f"Error reading file {filename}: {e}")
    
    return ip_details

def get_all_ip_scan_details1():
    """
    Retrieve the most recent scan details for all IP addresses with error handling
    
    Returns:
        list: Most recent scan details for each IP address
    """
    ip_details = []
    
    # Check if ipaddr directory exists
    if not os.path.exists("ipaddr"):
        st.warning("IP address details directory not found.")
        return ip_details

    # Check if directory is empty
    ip_files = [f for f in os.listdir("ipaddr") if f.endswith("_details.json")]
    
    if not ip_files:
        st.info("No IP scan details found. Run a scan to generate details.")
        return ip_details

    # Process each JSON file
    for filename in ip_files:
        filepath = os.path.join("ipaddr", filename)
        try:
            with open(filepath, 'r') as f:
                file_content = f.read().strip()
                
                # Check if file is empty
                if not file_content:
                    st.warning(f"Empty file found: {filename}")
                    continue
                
                # Attempt to parse JSON
                try:
                    all_ip_data = json.loads(file_content)
                    
                    # Get the most recent scan (last item in the list)
                    if all_ip_data and isinstance(all_ip_data, list):
                        latest_ip_data = all_ip_data[-1]
                        
                        # Validate the structure of the JSON
                        required_keys = ['ip_address', 'open_ports', 'filtered_ports', 'web_vulnerabilities']
                        if all(key in latest_ip_data for key in required_keys):
                            ip_details.append(latest_ip_data)
                        else:
                            st.warning(f"Incomplete data in file: {filename}")
                
                except json.JSONDecodeError:
                    st.error(f"JSON decoding error in file: {filename}")
        
        except IOError as e:
            st.error(f"Error reading file {filename}: {e}")
    
    return ip_details


def parse_nmap_results(filepath):
    """Parse Nmap scan results."""
    open_ports = []
    filtered_ports = []
    host_status = ""
    mysql_version_detected = False
    target_hostname = None
    target_ip = None
    start_time = None
    end_time = None

    # Parse the XML file
    tree = ET.parse(filepath)
    root = tree.getroot()

    # Extract scan start and end times
    scan_info = root.find("runstats")
    if scan_info is not None:
        start_time_attr = root.attrib.get("start")
        if start_time_attr:
            start_time = datetime.fromtimestamp(int(start_time_attr)).strftime(
                "%B %d, %Y %H:%M:%S"
            )
        end_time_element = scan_info.find("finished")
        if end_time_element is not None:
            end_time_attr = end_time_element.attrib.get("time")
            if end_time_attr:
                end_time = datetime.fromtimestamp(int(end_time_attr)).strftime(
                    "%B %d, %Y %H:%M:%S"
                )

    # Extract target IP and hostname
    host = root.find("host")
    if host is not None:
        address = host.find("address")
        if address is not None:
            target_ip = address.attrib.get("addr")
            target_hostname = address.attrib.get(
                "addr", "Unknown"
            )  # Assuming hostname might not be available

        # Extract host status
        status = host.find("status")
        if status is not None:
            host_status = status.attrib.get("state", "Unknown")

    # Extract ports
    ports = root.findall(".//port")
    for port in ports:
        port_id = port.attrib.get("portid")
        service = port.find("service")
        state = port.find("state")

        if state is not None and state.attrib.get("state") == "open":
            service_name = (
                service.attrib.get("name", "Unknown")
                if service is not None
                else "Unknown"
            )
            open_ports.append([port_id, service_name])
            if "mysql" in service_name.lower():
                mysql_version_detected = True
        elif state is not None and state.attrib.get("state") == "filtered":
            service_name = (
                service.attrib.get("name", "Unknown")
                if service is not None
                else "Unknown"
            )
            filtered_ports.append([port_id, service_name])

    # Calculate total ports scanned
    total_ports_scanned = len(ports)

    return (
        open_ports,
        filtered_ports,
        host_status,
        mysql_version_detected,
        target_hostname,
        target_ip,
        start_time,
        end_time,
        total_ports_scanned,
    )

def parse_nikto_results(filepath):
    """Parse Nikto scan results using lxml with a direct XML parse."""
    findings = []
    start_time = None
    total_tests_run = 0
    target_ip = None
    hostname = None
    target_port = None
    web_server = None
    elapsed_time_attr = "No elapsed time"
    
    try:
        # Parse the XML file directly
        tree = etree.parse(filepath)
        root = tree.getroot()
        
        # If the root isn't <niktoscan>, try to find it within the tree
        if root.tag != "niktoscan":
            root = root.find("niktoscan")
        if root is None:
            logger.log("No <niktoscan> element found in the XML.")
            return [], None, None, None, None, None, 0, elapsed_time_attr
        
        scandetails = root.find("scandetails")
        if scandetails is not None:
            start_time_attr = scandetails.attrib.get("starttime")
            if start_time_attr:
                start_time = datetime.strptime(start_time_attr, '%Y-%m-%d %H:%M:%S').strftime('%B %d, %Y %H:%M:%S')
            target_ip = scandetails.attrib.get("targetip", "No IP")
            hostname = scandetails.attrib.get("targethostname", "No Hostname")
            target_port = scandetails.attrib.get("targetport", "No Port")
            web_server = scandetails.attrib.get("targetbanner", "No Web Server")
            
            items = scandetails.findall("item")
            for item in items:
                description = item.findtext("description", default="No description")
                findings.append(description)
            total_tests_run = len(items)
            elapsed_time_attr = scandetails.attrib.get("elapsed", "No elapsed time")
        else:
            logger.log("No <scandetails> element found in the Nikto XML.")
    except Exception as e:
        logger.log(f"Error parsing Nikto XML file: {e}")
        return [], None, None, None, None, None, 0, elapsed_time_attr

    return findings, start_time, target_ip, hostname, target_port, web_server, total_tests_run, elapsed_time_attr



def execute_scans1(networks, output_dir, run_nmap, run_nikto):
    scan_results = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(networks)) as executor:
        futures = {}

        for network in networks:
            if run_nmap:
                futures[executor.submit(run_nmap_scan, network, output_dir)] = network
            if run_nikto:
                futures[executor.submit(run_nikto_scan, network, output_dir)] = network

        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            result = future.result()
            if result:
                scan_results[ip] = result

    # Generate a report for each scanned IP
    report_paths = []
    for ip in scan_results.keys():  # Ensure only successful scans are processed
        report_path = generate_report(output_dir, run_nmap, run_nikto, ip)
        report_paths.append(report_path)

    return report_paths



def execute_scans(networks, output_dir, run_nmap, run_nikto, batch_size=10):
    """
    Execute scans in batches, with a maximum of batch_size tasks running per batch.
    Nmap is always run.
    """
    scan_results = {}
    total_networks = len(networks)
    batches = math.ceil(total_networks / batch_size)
    
    for b in range(batches):
        batch_networks = networks[b * batch_size:(b + 1) * batch_size]
        with concurrent.futures.ThreadPoolExecutor(max_workers=batch_size) as executor:
            futures = {}
            # Submit tasks for the current batch
            for network in batch_networks:
                futures[executor.submit(run_nmap_scan, network, output_dir)] = network
                if run_nikto:
                    futures[executor.submit(run_nikto_scan, network, output_dir)] = network

            # Wait for all futures in this batch to complete
            for future in concurrent.futures.as_completed(futures):
                ip = futures[future]
                try:
                    result = future.result()
                    if result:
                        scan_results[ip] = result
                except Exception as e:
                    print(f"Error scanning {ip}: {e}")
                    
        # Optionally, add a delay between batches if needed
        # time.sleep(1)
    # After all batches are done, generate reports for each IP as needed.
    report_paths = []
    for ip in scan_results.keys():
        report_path = generate_report(output_dir, run_nmap, run_nikto, ip)
        report_paths.append(report_path)
    return report_paths

def get_cvss_data(cve_id):
    load_dotenv()  # loads variables from .env into the environment
    API_KEY = os.getenv("API_KEY")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        headers = {"apiKey": API_KEY}  # Use your NVD API key here
        response = requests.get(url, headers=headers, timeout=10)
    except requests.exceptions.RequestException as e:
        print(f"Request error for {cve_id}: {e}")
        return None

    if response.status_code == 200:
        data = response.json()
        try:
            vulnerabilities = data.get("vulnerabilities", [])
            if vulnerabilities:
                vuln = vulnerabilities[0]
                cve_info = vuln.get("cve", {})
                metrics = cve_info.get("metrics", {})
                # Extract remediation information from NVD references:
                references = cve_info.get("references", [])
                remediation_info = []
                for ref in references:
                    ref_url = ref.get("url", "")
                    # Look for patch or update hints in the URL text
                    if "patch" in ref_url.lower() or "update" in ref_url.lower():
                        remediation_info.append(ref_url)
                remediation = "; ".join(remediation_info) if remediation_info else (
                    "Vendor Remediation: Update to the latest version as per vendor advisory."
                )
                # Try CVSS v3.1 first
                if "cvssMetricV31" in metrics:
                    cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                    descriptions = cve_info.get("descriptions", [])
                    eng_desc = next((d.get("value") for d in descriptions if d.get("lang")=="en"), "N/A")
                    return {
                        "baseScore": cvss_data.get("baseScore"),
                        "baseSeverity": cvss_data.get("baseSeverity"),
                        "attackVector": cvss_data.get("attackVector"),
                        "privilegesRequired": cvss_data.get("privilegesRequired"),
                        "confidentialityImpact": cvss_data.get("confidentialityImpact"),
                        "integrityImpact": cvss_data.get("integrityImpact"),
                        "availabilityImpact": cvss_data.get("availabilityImpact"),
                        "vectorString": cvss_data.get("vectorString"),
                        "description": eng_desc,
                        "remediation": remediation,
                        "exploitabilityScore": metrics["cvssMetricV31"][0].get("exploitabilityScore"),
                        "impactScore": metrics["cvssMetricV31"][0].get("impactScore")
                    }
                elif "cvssMetricV30" in metrics:
                    cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                    descriptions = cve_info.get("descriptions", [])
                    eng_desc = next((d.get("value") for d in descriptions if d.get("lang")=="en"), "N/A")
                    return {
                        "baseScore": cvss_data.get("baseScore"),
                        "baseSeverity": cvss_data.get("baseSeverity"),
                        "attackVector": cvss_data.get("attackVector"),
                        "privilegesRequired": cvss_data.get("privilegesRequired"),
                        "confidentialityImpact": cvss_data.get("confidentialityImpact"),
                        "integrityImpact": cvss_data.get("integrityImpact"),
                        "availabilityImpact": cvss_data.get("availabilityImpact"),
                        "vectorString": cvss_data.get("vectorString"),
                        "description": eng_desc,
                        "remediation": remediation,
                        "exploitabilityScore": metrics["cvssMetricV30"][0].get("exploitabilityScore"),
                        "impactScore": metrics["cvssMetricV30"][0].get("impactScore")
                    }
                elif "cvssMetricV2" in metrics:
                    cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                    descriptions = cve_info.get("descriptions", [])
                    eng_desc = next((d.get("value") for d in descriptions if d.get("lang")=="en"), "N/A")
                    return {
                        "baseScore": cvss_data.get("baseScore"),
                        "baseSeverity": metrics["cvssMetricV2"][0].get("baseSeverity"),
                        "attackVector": cvss_data.get("accessVector"),
                        "privilegesRequired": cvss_data.get("authentication"),
                        "confidentialityImpact": cvss_data.get("confidentialityImpact"),
                        "integrityImpact": cvss_data.get("integrityImpact"),
                        "availabilityImpact": cvss_data.get("availabilityImpact"),
                        "vectorString": cvss_data.get("vectorString"),
                        "description": eng_desc,
                        "remediation": remediation,
                        "exploitabilityScore": metrics["cvssMetricV2"][0].get("exploitabilityScore"),
                        "impactScore": metrics["cvssMetricV2"][0].get("impactScore")
                    }
            else:
                print(f"No vulnerabilities found for {cve_id}")
                return None
        except Exception as e:
            print(f"Error parsing metrics for {cve_id}: {e}")
            return None
    else:
        print(f"Error fetching {cve_id}: HTTP {response.status_code}")
        return None

def extract_cves_nmap(xml_file):
    cve_list = set()
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for elem in root.findall(".//script"):
            if "output" in elem.attrib:
                cves = re.findall(r'CVE-\d{4}-\d+', elem.attrib["output"])
                cve_list.update(cves)
    except Exception as e:
        print(f"Error parsing Nmap XML: {e}")
    return list(cve_list)



def create_severity_pie_chart(severity_counts):
    """
    Create a vibrant pie chart with a legend (without text over the pie).
    The legend shows each severity label with its count.
    Example: {"CRITICAL": 1, "HIGH": 3, "MEDIUM": 2, "LOW": 0, "INFO": 5}
    """
    # Increase drawing size to make room for legend
    drawing = Drawing(500, 250)
    pie = Pie()
    pie.x = 100
    pie.y = 50
    pie.width = 150
    pie.height = 150

    # Use only values for the pie (no internal labels)
    labels = list(severity_counts.keys())
    values = list(severity_counts.values())
    pie.data = values
    pie.labels = []  # Remove text labels from the pie chart

    # Use your custom vibrant colors
    vibrant_colors = {
        "CRITICAL": colors.HexColor("#ed1c24"),  # red
        "HIGH": colors.HexColor("#ff7f27"),       # orange
        "MEDIUM": colors.HexColor("#fff200"),      # yellow
        "LOW": colors.HexColor("#22b14c"),         # green
        "INFO": colors.HexColor("#d7e2e6")         # grey
    }

    
    # Assign colors to slices based on severity label order
    for i, label in enumerate(labels):
        if label in vibrant_colors:
            if i < len(pie.slices):
                pie.slices[i].fillColor = vibrant_colors[label]
        else:
            if i < len(pie.slices):
                pie.slices[i].fillColor = colors.grey

    drawing.add(pie)

    # Add a manual legend with the count for each category.
    legend_x = 300
    legend_y = 170
    box_size = 10
    spacing = 15
    for i, label in enumerate(labels):
        # Draw a colored box for the legend
        legend_box = Rect(legend_x, legend_y - i * spacing, box_size, box_size, fillColor=vibrant_colors.get(label, colors.grey))
        drawing.add(legend_box)
        # Add label text with count next to the box
        count = severity_counts.get(label, 0)
        legend_text = String(legend_x + box_size + 5, legend_y - i * spacing, f"{label}: {count}", fontSize=10)
        drawing.add(legend_text)
        
    return drawing

def generate_report(output_dir, run_nmap, run_nikto, target_ip):
    """Enhanced report generation for a specific target IP with dynamic section numbering.
    Skips Nmap/Nikto sections if their files aren't present."""
    # New file name format: hourminsec_ddmmyy_scan_report_ipaddress.pdf
    report_path = os.path.join("reports", f"{datetime.now().strftime('%H%M%S_%d%m%y')}_scan_report_{target_ip.replace('.', '_')}.pdf")
    
    # Define file paths
    nmap_file = os.path.join(output_dir, f"nmap_output_{target_ip.replace('.', '_')}.xml")
    nikto_file = os.path.join(output_dir, f"nikto_output_{target_ip.replace('.', '_')}.xml")
    
    # Parse Nmap data if available
    if run_nmap and os.path.exists(nmap_file):
        (open_ports,
         filtered_ports,
         host_status,
         mysql_version_detected,
         target_hostname,
         parsed_target_ip,
         nmap_start_time,
         nmap_end_time,
         total_ports_scanned) = parse_nmap_results(nmap_file)
    else:
        open_ports = []
        filtered_ports = []
        host_status = None
        mysql_version_detected = False
        target_hostname = None
        nmap_start_time = None
        nmap_end_time = None
        total_ports_scanned = None

    # Parse Nikto data if available
    if run_nikto and os.path.exists(nikto_file):
        (nikto_findings,
         nikto_start_time,
         nikto_target_ip,
         nikto_hostname,
         target_port,
         web_server,
         total_tests_run,
         elapsed_time) = parse_nikto_results(nikto_file)
    else:
        nikto_findings = []
        nikto_start_time = None
        nikto_hostname = None
        target_port = None
        web_server = None
        total_tests_run = None
        elapsed_time = None

    # Extract CVE IDs from the Nmap XML file (assumes nmap_file exists)
    all_cves = extract_cves_nmap(nmap_file)
    # Build a CVSS data dictionary for each CVE
    cvss_data_dict = {cve: get_cvss_data(cve) for cve in all_cves}
    target_hostname = resolve_ip_to_domain(target_ip)

    # Save IP details (even if empty)
    save_ip_details(target_ip, open_ports, filtered_ports, nikto_findings, cvss_data_dict)
    
    doc = SimpleDocTemplate(report_path, pagesize=letter)
    styles = getSampleStyleSheet()
    
    # Custom Styles
    title_style = styles["Title"]
    heading_style = styles["Heading1"]
    normal_style = styles["Normal"]
    section_heading_style = ParagraphStyle("SectionHeading", parent=styles["Heading2"], spaceAfter=12, fontSize=14)
    
    content = []
        
    # Title
    content.append(Paragraph("ScanPulse Report", title_style))
    content.append(Spacer(1, 12))

    section_no = 1  # Dynamic section numbering
    
    # 1. Introduction (always included)
    content.append(Paragraph(f"{section_no}. Introduction", heading_style))
    content.append(Paragraph(f"Date of Report: {datetime.now().strftime('%B %d, %Y')}", normal_style))
    content.append(Paragraph(f"Target IP: {target_ip}", normal_style))
    content.append(Paragraph(f"Target Hostname: {target_hostname if target_hostname else 'N/A'}", normal_style))
    content.append(Paragraph("Scan Performed By: ScanPulse - Automated Detection and Security Assessment tool", normal_style))
    content.append(Paragraph("Purpose: Identify vulnerabilities and security issues in the target environment.", normal_style))
    content.append(Spacer(1, 12))
    section_no += 1

    # 2. Scan Summary (only if at least one scan is available)
    scan_sections = []  # To hold sub-sections for scan summary
    subsec_no = 1
    if run_nmap and os.path.exists(nmap_file):
        scan_sections.append(Paragraph(f"{section_no}.{subsec_no} Nmap Scan Summary", section_heading_style))
        subsec_no += 1
        scan_sections.append(Paragraph(f"Scan Start Time: {nmap_start_time if nmap_start_time else 'N/A'}", normal_style))
        scan_sections.append(Paragraph(f"Scan End Time: {nmap_end_time if nmap_end_time else 'N/A'}", normal_style))
        scan_sections.append(Paragraph(f"Total Ports Scanned: {total_ports_scanned if total_ports_scanned else 'N/A'}", normal_style))
        if open_ports:
            scan_sections.append(Paragraph("Open Ports:", normal_style))
            table_data = [["Port Id", "Service Name"]] + [[port, service] for port, service in open_ports]
            table = Table(table_data, colWidths=[doc.width / 3.0] * 2)
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), "#f0f0f0"),
                ("TEXTCOLOR", (0, 0), (-1, 0), "#000000"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("GRID", (0, 0), (-1, -1), 1, "#d0d0d0"),
            ]))
            scan_sections.append(table)
        if filtered_ports:
            scan_sections.append(Paragraph("Filtered Ports:", normal_style))
            table_data = [["Port Id", "Service Name"]] + [[port, service] for port, service in filtered_ports]
            table = Table(table_data, colWidths=[doc.width / 3.0] * 2)
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), "#f0f0f0"),
                ("TEXTCOLOR", (0, 0), (-1, 0), "#000000"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("GRID", (0, 0), (-1, -1), 1, "#d0d0d0"),
            ]))
            scan_sections.append(table)
    if run_nikto and os.path.exists(nikto_file):
        scan_sections.append(Paragraph(f"{section_no}.{subsec_no} Nikto Scan Summary", section_heading_style))
        subsec_no += 1
        scan_sections.append(Paragraph(f"Scan Start Time: {nikto_start_time if nikto_start_time else 'N/A'}", normal_style))
        scan_sections.append(Paragraph(f"Number of Tests: {total_tests_run if total_tests_run is not None else 'N/A'}", normal_style))
        if nikto_findings:
            scan_sections.append(Paragraph("Findings:", normal_style))
            table_data = [[finding] for finding in nikto_findings]
            table = Table(table_data, colWidths=[doc.width])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), "#f0f0f0"),
                ("TEXTCOLOR", (0, 0), (-1, 0), "#000000"),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 1, "#d0d0d0"),
            ]))
            scan_sections.append(table)
    if scan_sections:
        content.append(Paragraph(f"{section_no}. Scan Summary", heading_style))
        content.extend(scan_sections)
        section_no += 1
    content.append(Spacer(1, 12))

    # 3. Vulnerability Assessment (only add if there's data from either scan)
    vulnerability_data_available = False
    if (open_ports or filtered_ports) or nikto_findings:
        vulnerability_data_available = True
    if vulnerability_data_available:
        content.append(Paragraph(f"{section_no}. Vulnerability Assessment", heading_style))
        subsec_counter = 1
        # If there are open ports (from Nmap)
        if open_ports:
            content.append(Paragraph(f"{section_no}.{subsec_counter} Open Ports and Services", section_heading_style))
            subsec_counter += 1
            styles_local = getSampleStyleSheet()
            normal_local = styles_local["Normal"]
            title_local = ParagraphStyle(name="TitleStyle", parent=styles_local["Normal"], fontSize=10, spaceAfter=2, textColor="black", fontName="Helvetica-Bold")
            recommendation_local = ParagraphStyle(name="RecommendationStyle", parent=styles_local["Normal"], fontSize=10, spaceAfter=8)
            open_ports_assessments = {
                "21": ("FTP", "Ensure that FTP is using secure configurations or replace with a secure alternative like SFTP."),
                "22": ("SSH", "Ensure SSH is secured with strong passwords or key-based authentication and disable root login if not needed."),
                "80": ("HTTP", "Ensure that the HTTP service is secure and consider using HTTPS for encrypted communication."),
                "443": ("HTTPS", "Ensure HTTPS configuration uses strong encryption standards and secure certificates."),
                "135": ("MSRPC", "Ensure that proper access controls are in place for MSRPC services to prevent unauthorized access."),
                "139": ("NetBIOS-SSN", "NetBIOS services should be restricted, and unused ports should be closed to avoid exposure to vulnerabilities."),
                "445": ("Microsoft-DS", "Ensure that SMB services are secured with proper authentication and access controls."),
                "3306": ("MySQL", "Ensure that the MySQL service is properly secured, and consider applying the latest patches and configurations to mitigate known vulnerabilities."),
                "8080": ("HTTP", "Ensure that the HTTP service is secure, apply patches, and consider using HTTPS."),
                "1022": ("EXP2", "Check for any potential vulnerabilities associated with EXP2 services and ensure proper security measures are in place."),
                "1023": ("NetVenueChat", "Ensure that any chat services are secured with proper authentication and are not exposed to unauthorized users."),
                "1026": ("LSA-or-NTerm", "Ensure that LSA and NT Termination services are secured and access is restricted."),
                "9898": ("Monkeycom", "Verify the security configuration of Monkeycom and ensure that it is not exposing sensitive information."),
                "9080": ("GLRPC", "Ensure that GLRPC services are secured with proper authentication and access controls to prevent unauthorized access.")
            }

            default_recommendation = "No specific recommendation available – please review the service configuration."

            for port, service in open_ports:
                content.append(Paragraph(f"Port {port} ({service}):", title_local))
                if port in open_ports_assessments:
                    _, recommendation = open_ports_assessments[port]
                else:
                    recommendation = default_recommendation
                content.append(Paragraph(f"Recommendation: {recommendation}", recommendation_local))
        # If there are Nikto findings
        if nikto_findings:
            content.append(Paragraph(f"{section_no}.{subsec_counter} Web Application Security", section_heading_style))
            subsec_counter += 1
            vulnerability_details = {
                "ETags": {
                    "description": "The server is leaking inode information via ETags.",
                    "impact": "An attacker can gain insights into the file system, potentially aiding further attacks.",
                    "recommendation": [
                        "Disable the use of ETags.",
                        "Review and sanitize headers."
                    ]
                },
                "X-Frame-Options": {
                    "description": "The X-Frame-Options header is not present.",
                    "impact": "This may allow clickjacking attacks, where an attacker deceives users into clicking on hidden or malicious elements.",
                    "recommendation": [
                        "Implement the X-Frame-Options header (preferably 'DENY' or 'SAMEORIGIN').",
                        "Conduct regular security audits."
                    ]
                },
                "Directory Listing": {
                    "description": "The server is configured to allow directory listing.",
                    "impact": "Sensitive files and directories may be exposed, aiding reconnaissance by attackers.",
                    "recommendation": [
                        "Disable directory listing in the server configuration.",
                        "Ensure proper access controls on directories."
                    ]
                },
                "Default Files": {
                    "description": "Default or sample files (e.g., readme, test pages) are present.",
                    "impact": "These files can disclose configuration details or sensitive information.",
                    "recommendation": [
                        "Remove or secure default/sample files.",
                        "Review server documentation to disable unnecessary sample content."
                    ]
                },
                "SSL/TLS Weaknesses": {
                    "description": "The server uses outdated SSL/TLS protocols or weak ciphers.",
                    "impact": "This can allow attackers to intercept or tamper with communications.",
                    "recommendation": [
                        "Upgrade to the latest secure protocols (e.g., TLS 1.2 or 1.3).",
                        "Disable weak ciphers and ensure proper certificate configuration."
                    ]
                },
                "Server Banner Disclosure": {
                    "description": "The server discloses detailed banner information (e.g., software version).",
                    "impact": "Attackers can use this information to identify known vulnerabilities associated with specific versions.",
                    "recommendation": [
                        "Suppress or modify banner information to reveal minimal details.",
                        "Use a web application firewall (WAF) to hide or alter server responses."
                    ]
                },
                "Cross-Site Scripting (XSS)": {
                    "description": "Potential XSS vulnerabilities were identified on the web application.",
                    "impact": "Attackers can inject malicious scripts, which may compromise user data or session integrity.",
                    "recommendation": [
                        "Sanitize all user inputs.",
                        "Implement proper output encoding.",
                        "Use Content Security Policy (CSP) headers."
                    ]
                }
            }

            styles_local = getSampleStyleSheet()
            normal_local = styles_local["Normal"]
            title_local = ParagraphStyle(name="TitleStyle", parent=styles_local["Normal"], fontSize=10, spaceAfter=2, textColor="black", fontName="Helvetica-Bold")
            description_local = ParagraphStyle(name="DescriptionStyle", parent=styles_local["Normal"], fontSize=10, spaceAfter=2)
            impact_local = ParagraphStyle(name="ImpactStyle", parent=styles_local["Normal"], fontSize=10, spaceAfter=2)
            recommendation_local = ParagraphStyle(name="RecommendationStyle", parent=styles_local["Normal"], fontSize=10, spaceAfter=2)
            for finding in nikto_findings:
                # Attempt to match the finding to one of our defined vulnerability keys
                found_key = None
                for key in vulnerability_details.keys():
                    if key.lower() in finding.lower():
                        found_key = key
                        break
                if found_key:
                    details = vulnerability_details[found_key]
                else:
                    details = {
                        "description": "No detailed information available.",
                        "impact": "N/A",
                        "recommendation": ["Further investigation is recommended."]
                    }
                
                content.append(Paragraph(f"Finding: {finding}", title_local))
                content.append(Paragraph(f"Description: {details['description']}", description_local))
                content.append(Paragraph(f"Impact: {details['impact']}", impact_local))
                content.append(Paragraph("Recommendations:", normal_local))
                for rec in details["recommendation"]:
                    content.append(Paragraph(f"- {rec}", recommendation_local))
                content.append(Paragraph(" ", section_heading_style))

        section_no += 1

    # 4. Vulnerability Risk & Remediation Metrics Section 
    content.append(Paragraph(f"{section_no}. Vulnerability Risk & Remediation Metrics", heading_style))
    section_no += 1
    content.append(Spacer(1, 12))
    
    # Check if we have any valid CVSS data (at least one entry is not None)
    has_cvss_data = any(info is not None for info in cvss_data_dict.values())

    if not has_cvss_data:
        content.append(Paragraph("No known vulnerabilities were found for the scanned IP address. This could mean that the target is well-secured or that no vulnerabilities have been reported in our current data sources. Consider re-running the scan later if new vulnerabilities are published.", normal_style))
        content.append(Spacer(1, 12))
    else:
        # Dynamically aggregate severity counts for the pie chart
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for info in cvss_data_dict.values():
            if info is not None:
                sev = info.get("baseSeverity", "INFO").upper()
                if sev in severity_counts:
                    severity_counts[sev] += 1
                else:
                    severity_counts[sev] = 1
            else:
                severity_counts["INFO"] += 1

        # Create and add the pie chart
        chart_drawing = create_severity_pie_chart(severity_counts)
        content.append(chart_drawing)
        content.append(Spacer(1, 12))

        # List detailed CVSS information for each CVE
        for cve, info in cvss_data_dict.items():
            content.append(Paragraph(f"<b>{cve}</b>", heading_style))
            if info is None:
                content.append(Paragraph("No data available.", normal_style))
            else:
                bullet_items = [
                    f"Base Score: {info.get('baseScore', 'N/A')}",
                    f"Severity: {info.get('baseSeverity', 'N/A')}",
                    f"Attack Vector: {info.get('attackVector', 'N/A')}",
                    f"Privileges Required: {info.get('privilegesRequired', 'N/A')}",
                    f"Confidentiality Impact: {info.get('confidentialityImpact', 'N/A')}",
                    f"Integrity Impact: {info.get('integrityImpact', 'N/A')}",
                    f"Description: {info.get('description', 'N/A')}",
                    f"Remediation: {info.get('remediation', 'Vendor Remediation: Update to the latest version as per vendor advisory.')}"
                ]
                for item in bullet_items:
                    content.append(Paragraph(f"• {item}", normal_style))
            content.append(Spacer(1, 12))


    # 5. Conclusion
    content.append(Paragraph(f"{section_no}. Conclusion", heading_style))
    content.append(Paragraph("This assessment highlights the key areas where the target system can be improved. Addressing the identified issues will enhance the security posture and reduce potential risks. Regular security assessments and best practices should be followed to maintain a secure environment.", normal_style))
    content.append(Spacer(1, 12))
    section_no += 1

    # content.append(PageBreak())
    
    # 6. Appendices - dynamic based on available scan data
    tools_used = []
    references = []
    if run_nmap and os.path.exists(nmap_file):
        tools_used.append("- Nmap: Network scanner for identifying open ports and services.")
        references.append("- Nmap Documentation: https://nmap.org/docs.html")
    if run_nikto and os.path.exists(nikto_file):
        tools_used.append("- Nikto: Web server scanner for identifying common vulnerabilities and misconfigurations.")
        references.append("- Nikto Documentation: https://cirt.net/Nikto2")

    if tools_used or references:
        content.append(Paragraph(f"{section_no}. Appendices", heading_style))
        content.append(Spacer(1, 12))
        subsec = 1
        if tools_used:
            content.append(Paragraph(f"{section_no}.{subsec} Tools Used", section_heading_style))
            for tool in tools_used:
                content.append(Paragraph(tool, normal_style))
            content.append(Spacer(1, 12))
            subsec += 1
        if references:
            content.append(Paragraph(f"{section_no}.{subsec} References", section_heading_style))
            for ref in references:
                content.append(Paragraph(ref, normal_style))
            content.append(Paragraph("- NVD: https://nvd.nist.gov/", normal_style))
            content.append(Spacer(1, 12))

    else:
        # If no scan data available, simply add an empty Appendices section
        content.append(Paragraph(f"{section_no}. Appendices", heading_style))
        content.append(Paragraph("- NVD: https://nvd.nist.gov/", normal_style))
        content.append(Spacer(1, 12))
    
    doc.build(content)
    return report_path


# Fetch scan files for Dashboard metrics
def fetch_scan_files():
    scan_files = glob.glob(os.path.join(os.getcwd(), "scan_results_*_*"))
    return scan_files


def fetchtoday_scan_files():
    # Get today's date in the format YYYY-MM-DD
    today_date = datetime.now().strftime('%Y%m%d')
    
    # Use glob to match files with today's date
    scan_files = glob.glob(os.path.join(os.getcwd(), f"scan_results_{today_date}_*"))
    
    return len(scan_files)

def create_trend_graphs(ip_details):
    """
    Create trend graphs for a specific IP address
    """
    # Ensure we have data
    if not ip_details:
        return [None, None, None]

    # Parse timestamps safely
    timestamps = []
    for entry in ip_details:
        try:
            timestamp = datetime.fromisoformat(entry['timestamp'])
            timestamps.append(timestamp)
        except Exception:
            continue

    # Ensure we have timestamps
    if not timestamps:
        return [None, None, None]

    # Count metrics for each scan
    open_ports_count = [len(entry.get('open_ports', [])) for entry in ip_details]
    filtered_ports_count = [len(entry.get('filtered_ports', [])) for entry in ip_details]
    vulnerabilities_count = [len(entry.get('web_vulnerabilities', [])) for entry in ip_details]
    
    # Create DataFrame for easier plotting
    df = pd.DataFrame({
        'Timestamp': timestamps,
        'Open Ports': open_ports_count,
        'Filtered Ports': filtered_ports_count,
        'Vulnerabilities': vulnerabilities_count
    })

    # Create line charts using Plotly Express
    open_ports_fig = px.line(
        df, x='Timestamp', y='Open Ports', 
        title=f"Open Ports Trend for {ip_details[0]['ip_address']}",
        color_discrete_sequence=['yellow']

    )
    
    filtered_ports_fig = px.line(
        df, x='Timestamp', y='Filtered Ports', 
        title=f"Filtered Ports Trend for {ip_details[0]['ip_address']}"
    )
    
    vulnerabilities_fig = px.line(
        df, x='Timestamp', y='Vulnerabilities', 
        title=f"Web Vulnerabilities Trend for {ip_details[0]['ip_address']}"
    )
    
    return [open_ports_fig, filtered_ports_fig, vulnerabilities_fig]

# Main application
def main():
    st.set_page_config(page_title="ScanPulse")
    st.title("🛡️ Security Assessment Dashboard")

    tabs = st.tabs(["📊 Dashboard", "🔍 Instant Scan", "📅 Scheduler", "📑 Reports","🌐 IP Details"])

    # Dashboard Tab
    with tabs[0]:
        scan_files = fetch_scan_files()
        total_files = len(scan_files)
        today_files = fetchtoday_scan_files()

        # Load IP details
        ip_details_raw = get_all_ip_scan_details()
        # Initialize total vulnerabilities count
        total_vulnerabilities = 0

        # Group scan details by IP address
        ip_details_grouped = {}
        for detail in ip_details_raw:
            ip = detail['ip_address']
            if ip not in ip_details_grouped:
                ip_details_grouped[ip] = []
            ip_details_grouped[ip].append(detail)

            # Count vulnerabilities for this IP
            severity_counts = detail.get("cvss_data", {}).get("severity_counts", {})
            total_vulnerabilities += sum(severity_counts.values())

        # Create two columns
        col1, col2 = st.columns(2)

        # Display metrics in separate columns
        with col1:
            st.metric("Total Scans", total_files, f"+{today_files}")

        with col2:
            st.metric("Total Vulnerabilities", total_vulnerabilities)

        if ip_details_raw:
            # Group scan details by IP address
            ip_details_grouped = {}
            for detail in ip_details_raw:
                ip = detail['ip_address']
                if ip not in ip_details_grouped:
                    ip_details_grouped[ip] = []
                ip_details_grouped[ip].append(detail)

            # Create overall summary chart
            data = []
            for ip, details in ip_details_grouped.items():
                latest_detail = details[-1]  # Most recent scan
                data.append({
                    'IP Address': ip,
                    'Open Ports': len(latest_detail['open_ports']),
                    'Filtered Ports': len(latest_detail['filtered_ports'])
                })

            # Create a DataFrame
            df = pd.DataFrame(data)

            # Create a Plotly Express stacked bar chart
            fig = px.bar(df, 
                x='IP Address', 
                y=['Open Ports', 'Filtered Ports'], 
                title="Open & Filtered Ports", 
                labels={"IP Address": "IP Address", "value": "Number of Ports"},
                barmode='stack')

            # Adjust layout for better readability
            fig.update_layout(
                height=400,
                width=800,
                xaxis_title="IP Addresses",
                yaxis_title="Number of Ports"
            )
            fig.update_xaxes(tickangle=45)

            # Show the overall summary chart
            st.plotly_chart(fig, use_container_width=True)

            # Create a DataFrame for web vulnerabilities count per IP address
            data_vuln = []
            for ip, details in ip_details_grouped.items():
                latest_detail = details[-1]
                vuln_count = len(latest_detail.get('web_vulnerabilities', []))
                data_vuln.append({
                    'IP Address': ip,
                    'Web Vulnerabilities': vuln_count
                })

            df_vuln = pd.DataFrame(data_vuln)

            # Create a Plotly Express bar chart for web vulnerabilities
            fig_vuln = px.bar(
                df_vuln, 
                x='IP Address', 
                y='Web Vulnerabilities', 
                title="Web Vulnerabilities",
                labels={"IP Address": "IP Address", "Web Vulnerabilities": "Number of Vulnerabilities"}
            )
            fig_vuln.update_layout(
                height=400,
                width=800,
                xaxis_title="IP Addresses",
                yaxis_title="Number of Vulnerabilities"
            )
            fig_vuln.update_xaxes(tickangle=45)

            st.plotly_chart(fig_vuln, use_container_width=True)
        
        # Fetch scan details
        ip_details_raw = get_all_ip_scan_details()

        if not ip_details_raw:
            st.warning("No scan data available.")
        else:
            # Group scan details by IP address
            ip_details_grouped = {}
            for detail in ip_details_raw:
                ip = detail['ip_address']
                if ip not in ip_details_grouped:
                    ip_details_grouped[ip] = []
                ip_details_grouped[ip].append(detail)

            # Create a DataFrame for total vulnerabilities count per IP, categorized by severity
            data_vuln_severity = []
            severity_levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

            for ip, details in ip_details_grouped.items():
                if details:  # Ensure the IP has scan details
                    latest_detail = details[-1]  # Get most recent scan
                    severity_counts = latest_detail.get("cvss_data", {}).get("severity_counts", {})

                    data_vuln_severity.append({
                        "IP Address": ip,
                        **{level: severity_counts.get(level, 0) for level in severity_levels}
                    })

            if data_vuln_severity:
                df_vuln_severity = pd.DataFrame(data_vuln_severity)

                # Create a Plotly Express stacked bar chart for total vulnerabilities
                fig_vuln_severity = px.bar(
                    df_vuln_severity, 
                    x='IP Address', 
                    y=severity_levels, 
                    title="Total Vulnerabilities",
                    labels={"IP Address": "IP Address", "value": "Number of Vulnerabilities", "variable": "Severity"},
                    barmode="stack",
                    color_discrete_map={"CRITICAL": "#ff0000", "HIGH": "#ff6600", 
                                        "MEDIUM": "#ffcc00", "LOW": "#00cc00", "INFO": "#999999"}
                )

                fig_vuln_severity.update_layout(
                    height=400,
                    width=800,
                    xaxis_title="IP Addresses",
                    yaxis_title="Number of Vulnerabilities"
                )
                fig_vuln_severity.update_xaxes(tickangle=45)

                # Display the graph
                st.plotly_chart(fig_vuln_severity, use_container_width=True)
            else:
                st.info("No vulnerability data available.")
        
           


        

    # Instant Scan Tab
    with tabs[1]:
        st.header("Instant Scan")

        st.subheader("Resolve Domain to IP")
        domain = st.text_input("Enter Domain Name", key="domain_input")

        if st.button("Resolve Domain"):
            if domain:
                resolved_ip = resolve_domain(domain)
                if resolved_ip:
                    st.success(f"Resolved {domain} to {resolved_ip}")
                else:
                    st.error("Invalid domain or unreachable host")
            else:
                st.warning("Please enter a domain name")

        # st.subheader("Resolve IP to Domain")
        # ip_address = st.text_input("Enter IP Address", key="ip_input")

        # if st.button("Resolve IP"):
        #     if ip_address:
        #         resolved_domain = resolve_ip_to_domain(ip_address)
        #         if resolved_domain:
        #             st.success(f"Resolved {ip_address} to {resolved_domain}")
        #         else:
        #             st.error("Invalid IP or no associated domain")
        #     else:
        #         st.warning("Please enter an IP address")

        st.subheader("Start scan")
        network_input = st.text_area(
            "Target Networks/IPs (one per line)",
            help="Enter target IP addresses or networks (e.g., 192.168.1.1 or 192.168.1.0/24)"
        )

        col1, col2 = st.columns(2)
        with col1:
            run_nmap = st.checkbox("Run Nmap Scan", value=True)
        with col2:
            run_nikto = st.checkbox("Run Nikto Scan")

        # timeout_value = st.slider(
        #     "Set scan timeout (seconds)", 
        #     min_value=30, 
        #     max_value=600, 
        #     value=300, 
        #     step=10
        # )

        if st.button("Start Scan", type="primary", use_container_width=True):
            networks = [n.strip() for n in network_input.split('\n') if n.strip()]
            valid_ips = process_targets(networks)
            print(valid_ips)
            if not valid_ips:
                st.error("No valid IPs or networks provided.")
                return
            if not networks:
                st.error("Please enter at least one target network/IP.")
                return
            invalid_ips = [ip for ip in valid_ips if not is_valid_ip(ip)]
            if invalid_ips:
                st.error(f"Invalid IP(s) detected: {', '.join(invalid_ips)}")
                return
            if not (run_nmap or run_nikto):
                st.error("Please select at least one scan type.")
                return

            output_dir = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            os.makedirs(output_dir, exist_ok=True)

            progress_bar = st.progress(0)
            status_text = st.empty()

            try:
                status_text.text("Starting parallel network scans...")
                progress_bar.progress(15)
                
                report_paths = execute_scans(valid_ips, output_dir, run_nmap, run_nikto)
                progress_bar.progress(75)
                status_text.text("Scan and reporting completed successfully!")
                progress_bar.progress(100)
                
                for path in report_paths:
                    with open(path, "rb") as file:
                        st.download_button(
                            label=f"Download Report {os.path.basename(path)}",
                            data=file,
                            file_name=os.path.basename(path),
                            mime="application/pdf"
                        )
                        
                st.subheader("Scan Logs")
                for log in logger.logs:
                    st.info(log)
                    
            except Exception as e:
                st.error(f"An error occurred during scanning: {str(e)}")


    # Scheduler Tab
    with tabs[2]:
        st.header("Scan Scheduler")

        schedule_networks = st.text_area("Target Networks/IPs for Scheduled Scans")

        col1, col2 = st.columns(2)
        with col1:
            schedule_nmap = st.checkbox("Schedule Nmap Scan", key="schedule_nmap")
        with col2:
            schedule_nikto = st.checkbox("Schedule Nikto Scan", key="schedule_nikto")

        schedule_frequency = st.selectbox(
            "Scan Frequency",
            ["Daily", "Weekly"]
        )

        if st.button("Set Schedule", type="primary", use_container_width=True):
            st.success(f"Scans scheduled to run {schedule_frequency.lower()}")

    # Reports Tab
    with tabs[3]:
            st.header("Scan Reports")

            if os.path.exists("reports"):
                reports = []
                for file in os.listdir("reports"):
                    if file.endswith(".pdf") and "_scan_report_" in file:
                        file_path = os.path.join("reports", file)
                        # Timestamp in format HHMMSS_DDMYY at the beginning of the filename
                        match = re.search(r"^(\d{6}_\d{6})_scan_report_", file)
                        if match:
                            timestamp_str = match.group(1)
                            try:
                                timestamp = datetime.strptime(timestamp_str, "%H%M%S_%d%m%y")
                                reports.append({
                                    "Date": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                                    "Timestamp": timestamp,  # Used for sorting
                                    "Filename": file,
                                    "Size": f"{os.path.getsize(file_path) / 1024:.1f} KB"
                                })
                            except ValueError:
                                continue

                # Sort reports by Timestamp descending (latest first)
                reports = sorted(reports, key=lambda r: r["Timestamp"], reverse=True)
                
                if reports:
                    # Add a search box to filter reports
                    search_query = st.text_input("Search Reports", "")
                    
                    reports_df = pd.DataFrame(reports)
                    if search_query:
                        reports_df = reports_df[
                            reports_df["Filename"].str.contains(search_query, case=False) |
                            reports_df["Date"].str.contains(search_query, case=False)
                        ]
                    
                    # Drop the Timestamp column for display purposes
                    reports_df = reports_df.drop("Timestamp", axis=1)
                    
                    st.dataframe(reports_df, use_container_width=True)
                    
                    for _, report in reports_df.iterrows():
                        with open(os.path.join("reports", report["Filename"]), "rb") as file:
                            st.download_button(
                                label=f"Download {report['Filename']}",
                                data=file,
                                file_name=report["Filename"],
                                mime="application/pdf",
                                key=f"download_{report['Filename']}"
                            )
                else:
                    st.info("No reports found. Run some scans to generate reports.")
            else:
                st.warning("Reports directory not found.")


    with tabs[4]:
        st.header("IP Address Scan Details")
        
        # Retrieve and display IP scan details
        ip_details = get_all_ip_scan_details()
        
        if ip_details:
            # Create tabs for each IP address
            ip_tabs = st.tabs([detail['ip_address'] for detail in ip_details])

            for i, detail in enumerate(ip_details):
                with ip_tabs[i]:
                    # CVSS Severity Pie Chart
                    if "cvss_data" in detail and "severity_counts" in detail["cvss_data"]:
                        st.subheader("CVSS Severity Distribution")
                        cvss_counts = detail["cvss_data"]["severity_counts"]
                        df_pie = pd.DataFrame({
                            "Severity": [level for level, count in cvss_counts.items() if count > 0],
                            "Count": [count for count in cvss_counts.values() if count > 0]
                        })
                        
                        if not df_pie.empty:
                            color_map = {"CRITICAL": "#ff0000", "HIGH": "#ff6600", "MEDIUM": "#ffcc00", "LOW": "#00cc00", "INFO": "#999999"}
                            overall_cvss = detail["cvss_data"].get("overall_vulnerability_level", "CVSS Severity Distribution")
                            fig_pie = px.pie(df_pie, names="Severity", values="Count", color="Severity", color_discrete_map=color_map, title=f"Overall CVSS Level: {overall_cvss}")
                            fig_pie.update_traces(textinfo='value')
                            fig_pie.update_layout(showlegend=True)
                            
                            st.plotly_chart(fig_pie, use_container_width=True)
                        else:
                            st.info("No vulnerabilities found.")

                    # Open Ports Section
                    st.subheader("Open Ports")
                    if detail.get('open_ports'):
                        open_ports_df = pd.DataFrame(detail['open_ports'])
                        st.dataframe(open_ports_df, use_container_width=True, hide_index=True)
                    else:
                        st.info("No open ports found")

                    # Filtered Ports Section
                    st.subheader("Filtered Ports")
                    if detail.get('filtered_ports'):
                        filtered_ports_df = pd.DataFrame(detail['filtered_ports'])
                        st.dataframe(filtered_ports_df, use_container_width=True, hide_index=True)
                    else:
                        st.info("No filtered ports found")

                    # Web Vulnerabilities Section
                    st.subheader("Web Vulnerabilities")
                    if detail.get('web_vulnerabilities'):
                        def flatten(lst):
                            flat = []
                            for item in lst:
                                if isinstance(item, list):
                                    flat.extend(flatten(item))
                                else:
                                    flat.append(item)
                            return flat

                        web_vulns = flatten(detail['web_vulnerabilities'])
                        web_vulns = list(dict.fromkeys(web_vulns))

                        if web_vulns:
                            vulnerabilities_df = pd.DataFrame({'Vulnerability': web_vulns})
                            st.dataframe(vulnerabilities_df, use_container_width=True, hide_index=True)
                        else:
                            st.info("No web vulnerabilities detected")
                    else:
                        st.info("No web vulnerabilities detected")

                    





# Main execution
if __name__ == "__main__":
    
    # Run main application
    main()