import os
import time
import requests
from bs4 import BeautifulSoup

# URL of the DVWA application
base_url = "http://127.0.0.1/DVWA/"
login_url = base_url + "login.php"
csrf_urls = [
    base_url + "vulnerabilities/csrf/",
    base_url + "vulnerabilities/csrf/submit.php"
]
security_url = base_url + "security.php"

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

# Function to run ZAP for CSRF testing
def run_zap_csrf_test(target_urls, cookies):
    if cookies:
        try:
            # Prepare cookies string for ZAP
            cookie_string = "; ".join([f"{key}={value}" for key, value in cookies.items()])
            
            # Start the ZAP scan
            for target_url in target_urls:
                zap_scan_url = f"{zap_base_url}/JSON/ascan/action/scan/?apikey={zap_api_key}&url={target_url}&recurse=true&inScopeOnly=false&scanPolicyName=&method=POST&postData=&contextId=&scanHeaders=true&cookie={cookie_string}"
                response = requests.get(zap_scan_url)
                scan_id = response.json().get("scan")
                print(f"Started ZAP scan for {target_url} with scan ID: {scan_id}")
                
                # Poll ZAP for scan status
                zap_scan_status_url = f"{zap_base_url}/JSON/ascan/view/status/?scanId={scan_id}"
                while True:
                    status_response = requests.get(zap_scan_status_url)
                    status = status_response.json().get("status")
                    if status == "100":
                        print(f"ZAP scan for {target_url} completed.")
                        break
                    print(f"ZAP scan for {target_url} is {status}% complete.")
                    time.sleep(5)
                
                # Get scan results
                zap_results_url = f"{zap_base_url}/JSON/core/view/alerts/?baseurl={target_url}&apikey={zap_api_key}"
                results_response = requests.get(zap_results_url)
                alerts = results_response.json().get("alerts", [])
                for alert in alerts:
                    print(f"Alert: {alert.get('alert')}, Risk: {alert.get('risk')}, URL: {alert.get('url')}, Param: {alert.get('param')}")
        except Exception as e:
            print(f"An error occurred during ZAP scan: {e}")
    else:
        print("No valid session cookies. ZAP scan will not run.")

if __name__ == "__main__":
    cookies = get_session_cookies()
    run_zap_csrf_test(csrf_urls, cookies)
