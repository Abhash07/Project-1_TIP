import requests
from bs4 import BeautifulSoup

# Base URL and credentials are handled here
base_url = "http://192.168.64.3/DVWA/"
dvwa_username = "admin"
dvwa_password = "password"
user_username = "gordonb"
user_password = "abc123"

# Function to login to DVWA and retrieve session cookies
def login_dvwa(username=dvwa_username, password=dvwa_password):
    login_url = base_url + "login.php"
    session = requests.Session()
    response = session.get(login_url)
    soup = BeautifulSoup(response.content, 'html.parser')
    user_token = soup.find('input', {'name': 'user_token'})['value']

    payload = {
        'username': username,
        'password': password,
        'Login': 'Login',
        'user_token': user_token
    }

    post_response = session.post(login_url, data=payload)

    if "Welcome to Damn Vulnerable Web Application" in post_response.text:
        print(f"Login successful for {username}.")
        return session
    else:
        print(f"Login failed for {username}. Check your credentials and DVWA configuration.")
        return None

# Function to set security level
def set_security_level(session, level):
    security_url = base_url + "security.php"
    response = session.get(security_url)
    soup = BeautifulSoup(response.content, 'html.parser')
    user_token = soup.find('input', {'name': 'user_token'})['value']

    payload = {
        'security': level,
        'seclev_submit': 'Submit',
        'user_token': user_token
    }

    response = session.post(security_url, data=payload)
    if level in response.text:
        print(f"Security level set to {level}.")
    else:
        print(f"Failed to set security level to {level}.")
    return session
