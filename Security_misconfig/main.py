from Directory_list import check_directory_listing
from default_cred import check_default_credentials
from sensitive import check_sensitive_files
from error_handling import check_error_handling

def check_security_misconfigurations(base_url):
    try:
        # Base URL should end with a '/'
        if not base_url.endswith('/'):
            base_url += '/'

        print("Checking for directory listing...")
        check_directory_listing(base_url)

        print("Checking for default credentials...")
        check_default_credentials(base_url, 'login.php')

        print("Checking for sensitive files...")
        check_sensitive_files(base_url)

        print("Checking for error handling...")
        check_error_handling(base_url)

    except Exception as e:
        print(f"An error occurred while testing for security misconfigurations: {e}")

# Example usage
if __name__ == "__main__":
    base_url = "http://127.0.0.1/dvwa/"  # Adjusted for local DVWA instance
    check_security_misconfigurations(base_url)
