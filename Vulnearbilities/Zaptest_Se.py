import os
import time
import requests
from bs4 import BeautifulSoup

# URL of the DVWA application
base_url = "http://192.168.64.3/DVWA/"
login_url = base_url + "login.php"
security_url = base_url + "security.php"
test_urls = [
    base_url + "config/",
    base_url + "includes/",
    base_url + "phpinfo.php",
]

# DVWA login credentials
dvwa_username = "admin"
dvwa_password = "password"

# OWASP ZAP API details
zap_api_key = "your_zap_api_key"  # Replace with your actual ZAP API key
zap_base_url = "http://127.0.0.1:8080"  # Adjust if your ZAP instance is running elsewhere

# Function to login to DVWA and retrieve session cookies
def get_session_cookies():
    try:
        with requests.Session() as session:
            # Get initial login page to retrieve the user_token
            response = session.get(login_url)
            soup = BeautifulSoup(response.content, 'html.parser')
            user_token = soup.find('input', {'name': 'user_token'})['value'] # type: ignore

            # Login payload
            payload = {
                'username': dvwa_username,
                'password': dvwa_password,
                'Login': 'Login',
                'user_token': user_token
            }

            # Perform login
            post_response = session.post(login_url, data=payload)

            # Check if login was successful
            if "Welcome to Damn Vulnerable Web Application" in post_response.text:
                print("Login successful.")
                cookies = session.cookies.get_dict()
                
                # Set security level to low
                set_security_level_to_low(session)
                
                # Return updated cookies
                cookies = session.cookies.get_dict()
                return cookies
            else:
                print("Login failed. Check your credentials and DVWA configuration.")
                return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

# Function to set security level to low
def set_security_level_to_low(session):
    try:
        response = session.get(security_url)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Find the security form and user token
        security_form = soup.find('form')
        user_token = security_form.find('input', {'name': 'user_token'})['value'] # type: ignore
        
        # Set security level to low
        security_payload = {
            'security': 'low',
            'seclev_submit': 'Submit',
            'user_token': user_token
        }
        session.post(security_url, data=security_payload)
        print("Security level set to low.")
    except Exception as e:
        print(f"An error occurred while setting security level: {e}")

# Function to check for security misconfigurations
def check_security_misconfigurations(session, test_urls):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Check for weak password policy
        response = session.get(base_url + "vulnerabilities/brute/", headers=headers)
        if "password" in response.text:
            print("Weak password policy detected.")
        
        # Check for insecure HTTP headers
        response = session.get(base_url, headers=headers)
        if "X-Content-Type-Options" not in response.headers:
            print("Missing X-Content-Type-Options header.")
        if "X-Frame-Options" not in response.headers:
            print("Missing X-Frame-Options header.")
        if "Content-Security-Policy" not in response.headers:
            print("Missing Content-Security-Policy header.")
        
        # Check for exposed sensitive files or directories
        for url in test_urls:
            response = session.get(url, headers=headers)
            if response.status_code == 200:
                print(f"Exposed sensitive file or directory detected: {url}")
        
        # Check for default credentials
        if dvwa_username == "admin" and dvwa_password == "password":
            print("Default credentials are being used.")
        
    except Exception as e:
        print(f"An error occurred during security misconfigurations check: {e}")

if __name__ == "__main__":
    cookies = get_session_cookies()
    if cookies:
        with requests.Session() as session:
            for cookie_name, cookie_value in cookies.items():
                session.cookies.set(cookie_name, cookie_value)
            check_security_misconfigurations(session, test_urls)
