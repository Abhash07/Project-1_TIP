import requests
from bs4 import BeautifulSoup

def test_buffer_overflow(session, base_url):
    # Define payloads with increasing size to test for buffer overflow
    payloads = [
        'A' * 100,   # Small payload
        'A' * 500,   # Larger payload
        'A' * 1000,  # Potentially dangerous size
        'A' * 5000,  # Likely to cause overflow
        'A' * 10000, # Very large payload to test the limits
    ]
    
    endpoint = 'vulnerabilities/overflow/'  # Hypothetical vulnerable endpoint

    for payload in payloads:
        data = {'input': payload, 'Submit': 'Submit'}
        response = session.post(base_url + endpoint, data=data)
        
        # Debug: Print response content and status code
        print(f"Response from {base_url}{endpoint} with payload size {len(payload)}:")
        print(response.status_code)
        print(response.text)
        
        # Check for signs of a buffer overflow vulnerability
        if response.status_code == 500:
            print(f"Buffer Overflow likely detected at {base_url}{endpoint} with payload size {len(payload)}.")
        elif "Segmentation fault" in response.text or "Exception" in response.text:
            print(f"Application crash detected at {base_url}{endpoint} with payload size {len(payload)}. Buffer overflow vulnerability is present.")
        else:
            print(f"No obvious Buffer Overflow detected at {base_url}{endpoint} with payload size {len(payload)}.")

# Example usage
if __name__ == "__main__":
    session = requests.Session()
    base_url = "http://127.0.0.1/DVWA/"  # Adjust for local DVWA instance
    
    # Ensure the session is logged in and security level is set to low
    from set_security import set_dvwa_security
    if set_dvwa_security(session, base_url, 'low'):
        test_buffer_overflow(session, base_url)
