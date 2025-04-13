import requests
from urllib.parse import urlparse
import nmap
import subprocess
import argparse
import logging
from art import text2art
from time import sleep
from fpdf import FPDF

# Configure logging
logging.basicConfig(
    filename="hsr_tool.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# Utility function to execute shell commands
def execute_command(command):
    try:
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
        if result.returncode == 0:
            return result.stdout
        else:
            logging.error(f"Command failed: {command}\n{result.stderr}")
            return None
    except Exception as e:
        logging.error(f"Error executing command: {command}\n{e}")
        return None

# Display tool logo
def display_logo():
    logo = text2art("HSR Tool", font="block")
    print(logo)

# Normalize URL
def normalize_url(url):
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"http://{url}"
        parsed = urlparse(url)
    return parsed.netloc, url

# Subdomain Enumeration using multiple methods
def enumerate_subdomains(domain, tools=["httpx", "subfinder"]):
    print("[*] Enumerating subdomains...")
    subdomains = set()
    for tool in tools:
        command = f"echo {domain} | {tool} -silent"
        output = execute_command(command)
        if output:
            subdomains.update(output.splitlines())
    return sorted(subdomains)

# DNS Records Discovery
def discover_dns_records(domain):
    print("[*] Discovering DNS Records...")
    records = {}
    try:
        for record_type in ["A", "MX", "NS", "TXT", "CNAME"]:
            command = f"dig {record_type} {domain} +short"
            result = execute_command(command)
            records[record_type] = result.splitlines() if result else []
    except Exception as e:
        logging.error(f"Error discovering DNS records: {e}")
    return records

# Network Scan for active hosts
def scan_network(network_range):
    print(f"[*] Scanning network range: {network_range}...")
    scanner = nmap.PortScanner()
    results = {}
    try:
        scanner.scan(hosts=network_range, arguments='-T4 -F')
        for host in scanner.all_hosts():
            results[host] = scanner[host].get('tcp', {})
    except Exception as e:
        logging.error(f"Error during network scan: {e}")
    return results

# Scan all ports for open ports using nmap
def scan_all_ports(domain):
    print(f"[*] Scanning all ports for target: {domain}...")
    scanner = nmap.PortScanner()
    results = {}
    try:
        scanner.scan(hosts=domain, arguments='-p- -T4')  # Scan all ports with fast timing
        for host in scanner.all_hosts():
            open_ports = [
                port for port, details in scanner[host].get('tcp', {}).items()
                if details['state'] == 'open'
            ]
            results[host] = open_ports
        return results
    except Exception as e:
        logging.error(f"Error during all-port scan: {e}")
        return {}
        
        # Web Technology Detection with retries and improved logging

def detect_technologies(url, retries=3, delay=5):
    print("[*] Detecting web technologies...")
    technologies = []
    attempt = 0
    while attempt < retries:
        try:
            response = requests.get(url, timeout=10)
            headers = response.headers
            if 'Server' in headers:
                technologies.append(f"Server: {headers['Server']}")
            if 'X-Powered-By' in headers:
                technologies.append(f"X-Powered-By: {headers['X-Powered-By']}")
            return technologies  # Exit if successful
        except requests.exceptions.RequestException as e:
            attempt += 1
            logging.error(f"Error during technology detection (attempt {attempt}/{retries}): {e}")
            if attempt < retries:
                sleep(delay)
            else:
                logging.error(f"Max retries reached. Could not fetch technologies for {url}.")
    return technologies

# Vulnerability Scanning using nuclei
def run_nuclei(domain):
    print("[*] Running vulnerability scanning with nuclei...")
    command = f"echo {domain} | nuclei -silent"
    return execute_command(command)

# Web Crawling using katana
def run_katana(domain):
    print("[*] Crawling the website using katana...")
    command = f"echo {domain} | katana -silent"
    return execute_command(command)

# Run All Features and save results to text and PDF files
def run_all_features(domain, network_range, debug=False):
    print("[*] Running all features...")
    results = []

    # Subdomain Enumeration
    subdomains = enumerate_subdomains(domain)
    subdomains_result = f"[*] Subdomains found: {len(subdomains)}\n{subdomains}\n"
    results.append(subdomains_result)

    # DNS Records
    dns_records = discover_dns_records(domain)
    dns_result = f"[*] DNS Records:\n{dns_records}\n"
    results.append(dns_result)

    # Network Scan
    if network_range:
        network_results = scan_network(network_range)
        network_scan_result = f"[*] Active hosts found: {len(network_results)}\n{network_results}\n"
        results.append(network_scan_result)

    # All-Ports Scan
    all_ports_results = scan_all_ports(domain)
    all_ports_result_text = f"[*] All Ports Scan Results:\n{all_ports_results}\n"
    results.append(all_ports_result_text)
    
    # Technology Detection
    technologies = detect_technologies(f"http://{domain}")
    tech_detection_result = f"[*] Technologies detected: {technologies}\n"
    results.append(tech_detection_result)

    # Vulnerability Scanning
    nuclei_results = run_nuclei(domain)
    vuln_scan_result = f"[*] Vulnerability Scanning Results:\n{nuclei_results}\n"
    results.append(vuln_scan_result)

    # Web Crawling
    crawl_results = run_katana(domain)
    web_crawl_result = f"[*] Crawled URLs:\n{crawl_results}\n"
    results.append(web_crawl_result)

    # Debugging Information
    if debug:
        logging.info("Detailed Results:\n" + "\n".join(results))

    # Save results to result.txt
    with open("result.txt", "w") as txt_file:
        txt_file.writelines("\n".join(results))
    print("[*] Results saved to result.txt")

    # Save results to result.pdf
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="HSR Tool Results", ln=True, align="C")
    pdf.ln(10)
    for result in results:
        pdf.multi_cell(0, 10, txt=result)
        pdf.ln(5)
    pdf.output("result.pdf")
    print("[*] Results saved to result.pdf")

# Main function
def main():
    display_logo()

    parser = argparse.ArgumentParser(description="HSR Automation Tool - Advanced Recon and Vulnerability Scanning")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., example.com)")
    parser.add_argument("-n", "--network", help="Network range for scanning (e.g., 192.168.1.0/24)")
    parser.add_argument("--run-all", action="store_true", help="Run all features")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()

    target_input = args.url.strip()
    network_range = args.network
    debug_mode = args.debug

    domain, normalized_url = normalize_url(target_input)

    if args.run_all:
        run_all_features(domain, network_range, debug_mode)
    else:
        print("[!] Please specify individual features or use --run-all to execute everything.")

if __name__ == "__main__":
    main()
