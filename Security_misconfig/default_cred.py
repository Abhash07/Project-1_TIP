import requests
from bs4 import BeautifulSoup

def check_default_credentials(session, base_url, login_endpoint):
    default_creds = [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('root', 'root'),
        ('user', 'password'),
        ('test', 'test'),
        ('guest', 'guest'),
        ('administrator', 'administrator'),
        ('demo', 'demo')
    ]
    
    for username, password in default_creds:
        response = session.get(base_url + login_endpoint)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Get the CSRF token from the login page
        user_token = soup.find('input', {'name': 'user_token'})['value'] # type: ignore
        
        login_data = {
            'username': username,
            'password': password,
            'Login': 'Login',
            'user_token': user_token
        }
        
        response = session.post(base_url + login_endpoint, data=login_data)
        
        # Debug: Print login response content
        print(f"Testing credentials {username}/{password}")
        print("Login response:")
        print(response.text)
        
        if "Welcome to Damn Vulnerable Web Application!" in response.text:
            print(f"Default credentials valid for {username}/{password}")
        else:
            print(f"Default credentials invalid for {username}/{password}")

# Example usage
if __name__ == "__main__":
    session = requests.Session()
    base_url = "http://127.0.0.1/DVWA/"  # Adjusted for local DVWA instance
    check_default_credentials(session, base_url, 'login.php')
