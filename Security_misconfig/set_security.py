import requests
from bs4 import BeautifulSoup

def set_dvwa_security(session, base_url, security_level='low'):
    # Login to DVWA
    login_data = {
        'username': 'admin',
        'password': 'password',
        'Login': 'Login'
    }
    login_url = base_url + 'login.php'
    response = session.get(login_url)
    soup = BeautifulSoup(response.content, 'html.parser')
    
    # Get the CSRF token from the login page
    user_token = soup.find('input', {'name': 'user_token'})['value'] # type: ignore
    login_data['user_token'] = user_token # type: ignore
    
    response = session.post(login_url, data=login_data)
    
    # Debug: Print login response content
    print("Login response:")
    print(response.text)
    
    if 'Welcome to Damn Vulnerable Web Application!' not in response.text:
        print("Failed to login to DVWA")
        return False

    # Set security level
    security_url = base_url + 'security.php'
    response = session.get(security_url)
    soup = BeautifulSoup(response.content, 'html.parser')
    token = soup.find('input', {'name': 'user_token'})['value'] # type: ignore
    
    security_data = {
        'security': security_level,
        'seclev_submit': 'Submit',
        'user_token': token
    }
    response = session.post(security_url, data=security_data)
    
    # Debug: Print security level response content
    print("Security level response:")
    print(response.text)
    
    if f'Security level set to {security_level}' in response.text:
        print(f"Security level set to {security_level}")
        return True
    else:
        print(f"Failed to set security level to {security_level}")
        return False

# Example usage
if __name__ == "__main__":
    base_url = "http://127.0.0.1/DVWA/"  # Adjusted for local DVWA instance
    session = requests.Session()
    set_dvwa_security(session, base_url)
