from Directory_list import check_directory_listing
from default_cred import check_default_credentials
from sensitive import check_sensitive_files
from error_handling import check_error_handling
from set_security import set_dvwa_security
from openports import check_open_ports
from missing_conf import check_security_headers, check_https_enforcement
from Comin import test_command_injection
from csrf import (
    test_complete_compromise,
    test_gaining_privileges,
    test_bypassing_protection,
    test_modifying_data,
    test_dos,
    check_csrfpay
    )
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
        
        print("Checking for open ports...")
        check_open_ports(host)
        
        print("Checking for missing security headers...")
        check_security_headers(base_url)

        print("Checking for HTTPS enforcement...")
        check_https_enforcement(base_url)
        
        print("Checking for command injection vulnerabilities...")
        test_command_injection(session, base_url)
        
        print("Checking for CSRF vulnerabilities...")
        test_complete_compromise(session, base_url)
        test_gaining_privileges(session, base_url)
        test_bypassing_protection(session, base_url)
        test_modifying_data(session, base_url)
        test_dos(session, base_url)
        check_csrfpay(session, base_url)

    except Exception as e:
        print(f"An error occurred while testing for security misconfigurations: {e}")

# Example usage
if __name__ == "__main__":
    base_url = "http://127.0.0.1/DVWA/"  # Adjusted for local DVWA instance
    host = "127.0.0.1"  # Adjusted for local DVWA instance
    check_security_misconfigurations(base_url)
