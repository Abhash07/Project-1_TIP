import requests
from bs4 import BeautifulSoup

# DVWA credentials
dvwa_username = 'admin'
dvwa_password = 'password'

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

# Modify your main function to include login
def main(url, payload_file, simulate_vulnerable=False):
    with requests.Session() as session:
        # Log in to DVWA
        dvwa_login(session, url + 'login.php')

        print(f"Starting XSS vulnerability scans on {url}...")

        # Load the payloads from the file
        xss_payloads = load_payloads(payload_file)

        # Scenario 1: Scan for reflected XSS
        print("Scanning for Reflected XSS...")
        scan_reflected_xss(url, xss_payloads, simulate_vulnerable)

        # Scenario 2: Scan for stored XSS
        print("Scanning for Stored XSS...")
        scan_stored_xss(url, xss_payloads, simulate_vulnerable)

        # Scenario 3: Scan for DOM-based XSS
        print("Scanning for DOM-based XSS...")
        scan_dom_xss(url, xss_payloads, simulate_vulnerable)

        # Scenario 4: Test bypassing basic filters (Obfuscated Payloads)
        print("Testing Obfuscated XSS...")
        test_obfuscated_xss(url, simulate_vulnerable)

        # Scenario 5: Test Multi-Vector XSS attack
        print("Testing Multi-Vector XSS...")
        test_multivector_xss(url, simulate_vulnerable)

        print(f"XSS vulnerability scans completed for {url}.")

# Modify the scan functions to use the session
def scan_reflected_xss(url, payloads, simulate_vulnerable=False):
    for payload in payloads:
        response = session.get(url, params={'name': payload})
        if simulate_vulnerable or payload in response.text:
            print(f"[Reflected XSS] Vulnerability found at {url} with payload: {payload}")
            return True
    return False

# Update other scan functions similarly...

if __name__ == "__main__":
    # Path to the file containing payloads
    payload_file = "xss_payloads.txt"

    # DVWA base URL
    base_url = "http://localhost/DVWA/"

    # Simulate Vulnerable Scenario
    print("Scenario: Demonstrating a Vulnerable URL")
    main(base_url, payload_file, simulate_vulnerable=True)


