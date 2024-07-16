import requests
from bs4 import BeautifulSoup

def get_session_cookies(base_url, dvwa_username, dvwa_password):
    login_url = base_url + "login.php"
    security_url = base_url + "security.php"
    
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
                set_security_level_to_low(session, security_url)
                
                # Return updated cookies
                cookies = session.cookies.get_dict()
                return cookies
            else:
                print("Login failed. Check your credentials and DVWA configuration.")
                return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def set_security_level_to_low(session, security_url):
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
