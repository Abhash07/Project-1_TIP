import requests
from Login import get_session_cookies
from test_misconfigurations import check_csrf

# URL of the DVWA application
base_url = "http://127.0.0.1/DVWA/"

# DVWA login credentials
dvwa_username = "admin"
dvwa_password = "password"

def main():
    cookies = get_session_cookies(base_url, dvwa_username, dvwa_password)
    if cookies:
        with requests.Session() as session:
            for cookie_name, cookie_value in cookies.items():
                session.cookies.set(cookie_name, cookie_value)
            check_csrf(session, base_url)
    else:
        print("Failed to get session cookies.")

if __name__ == "__main__":
    main()
