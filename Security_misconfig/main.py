from Directory_list import check_directory_listing
from default_cred import check_default_credentials
from sensitive import check_sensitive_files
from error_handling import check_error_handling
from set_security import set_dvwa_security
import requests

def check_security_misconfigurations(base_url):
    try:
        session = requests.Session()
        
        # Set DVWA security level to low
        if not set_dvwa_security(session, base_url, 'low'):
            return

        print("Checking for directory listing...")
        check_directory_listing(session, base_url)

        print("Checking for default credentials...")
        check_default_credentials(session, base_url, 'login.php')

        print("Checking for sensitive files...")
        check_sensitive_files(session, base_url)

        print("Checking for error handling...")
        check_error_handling(session, base_url)

    except Exception as e:
        print(f"An error occurred while testing for security misconfigurations: {e}")

# Example usage
if __name__ == "__main__":
    base_url = "http://127.0.0.1/DVWA/"  # Adjusted for local DVWA instance
    check_security_misconfigurations(base_url)
