import requests
import logging
from bs4 import BeautifulSoup

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# DVWA credentials
dvwa_username = 'admin'
dvwa_password = 'password'

# Function to read payloads from a file
def load_payloads(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

# Function to log in to DVWA
def dvwa_login(session, login_url):
    # Get the login page to retrieve CSRF token
    response = session.get(login_url)
    soup = BeautifulSoup(response.text, 'html.parser')
    user_token = soup.find('input', {'name': 'user_token'})['value']

    # Prepare login payload
    login_payload = {
        'username': dvwa_username,
        'password': dvwa_password,
        'Login': 'Login',
        'user_token': user_token
    }

    # Post the login data
    session.post(login_url, data=login_payload)
    logging.info("Logged in to DVWA.")

# Function to scan basic File Inclusion
def scan_basic_file_inclusion(session, url, payloads, simulate_vulnerable=False):
    for payload in payloads:
        logging.info(f"Testing Basic File Inclusion with payload: {payload}")
        response = session.get(url, params={'file': payload})
        if simulate_vulnerable or "root:" in response.text or payload in response.text:
            logging.info(f"[File Inclusion] Vulnerability found at {url} with payload: {payload}")
            return True
    return False

# Function to scan Remote File Inclusion (RFI)
def scan_remote_file_inclusion(session, url, payloads, simulate_vulnerable=False):
    for payload in payloads:
        logging.info(f"Testing Remote File Inclusion (RFI) with payload: {payload}")
        response = session.get(url, params={'file': payload})
        if simulate_vulnerable or "root:" in response.text or payload in response.text:
            logging.info(f"[Remote File Inclusion] Vulnerability found at {url} with payload: {payload}")
            return True
    return False

# Function to scan for Path Traversal (LFI with directory traversal)
def scan_path_traversal(session, url, payloads, simulate_vulnerable=False):
    for payload in payloads:
        logging.info(f"Testing Path Traversal with payload: {payload}")
        response = session.get(url, params={'file': payload})
        if simulate_vulnerable or "root:" in response.text or payload in response.text:
            logging.info(f"[Path Traversal] Vulnerability found at {url} with payload: {payload}")
            return True
    return False

# Function to test File Inclusion with null byte injection (only relevant in older PHP versions)
def scan_null_byte_injection(session, url, payloads, simulate_vulnerable=False):
    for payload in payloads:
        logging.info(f"Testing Null Byte Injection with payload: {payload}")
        response = session.get(url, params={'file': payload + '%00'})
        if simulate_vulnerable or "root:" in response.text or payload in response.text:
            logging.info(f"[Null Byte Injection] Vulnerability found at {url} with payload: {payload}")
            return True
    return False

# Function to test File Inclusion with encoding or obfuscation (Bypass filters)
def scan_obfuscated_file_inclusion(session, url, payloads, simulate_vulnerable=False):
    for payload in payloads:
        logging.info(f"Testing Obfuscated File Inclusion with payload: {payload}")
        response = session.get(url, params={'file': payload})
        if simulate_vulnerable or "root:" in response.text or payload in response.text:
            logging.info(f"[Obfuscated File Inclusion] Vulnerability found at {url} with payload: {payload}")
            return True
    return False

# Main function to run all File Inclusion scans
def main(url, payload_file, simulate_vulnerable=False):
    with requests.Session() as session:
        # Log in to DVWA
        dvwa_login(session, url + 'login.php')

        logging.info(f"Starting File Inclusion vulnerability scans on {url}...")

        # Load the payloads from the file
        file_inclusion_payloads = load_payloads(payload_file)

        # Scenario 1: Scan for Basic File Inclusion
        logging.info("Scanning for Basic File Inclusion...")
        scan_basic_file_inclusion(session, url + 'vulnerabilities/fi/', file_inclusion_payloads, simulate_vulnerable)

        # Scenario 2: Scan for Remote File Inclusion
        logging.info("Scanning for Remote File Inclusion (RFI)...")
        scan_remote_file_inclusion(session, url + 'vulnerabilities/fi/', file_inclusion_payloads, simulate_vulnerable)

        # Scenario 3: Scan for Path Traversal (LFI with directory traversal)
        logging.info("Scanning for Path Traversal...")
        scan_path_traversal(session, url + 'vulnerabilities/fi/', file_inclusion_payloads, simulate_vulnerable)

        # Scenario 4: Test for Null Byte Injection
        logging.info("Testing for Null Byte Injection...")
        scan_null_byte_injection(session, url + 'vulnerabilities/fi/', file_inclusion_payloads, simulate_vulnerable)

        # Scenario 5: Test for Obfuscated File Inclusion
        logging.info("Testing for Obfuscated File Inclusion...")
        scan_obfuscated_file_inclusion(session, url + 'vulnerabilities/fi/', file_inclusion_payloads, simulate_vulnerable)

        logging.info(f"File Inclusion vulnerability scans completed for {url}.")

if __name__ == "__main__":
    # Path to the file containing payloads
    payload_file = "file_inclusion_payloads.txt"

    # DVWA base URL
    base_url = "http://localhost/DVWA/"

    # Simulate Vulnerable Scenario
    logging.info("Scenario: Demonstrating a Vulnerable URL")
    main(base_url, payload_file, simulate_vulnerable=True)
