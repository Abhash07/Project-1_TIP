import requests

def check_default_credentials(base_url, login_endpoint):
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
        response = requests.post(base_url + login_endpoint, data={'username': username, 'password': password})
        if "Welcome" in response.text or response.status_code == 200:
            print(f"Default credentials valid for {username}/{password}")
        else:
            print(f"Default credentials invalid for {username}/{password}")

# Example usage
if __name__ == "__main__":
    base_url = "http://127.0.0.1/dvwa/"  # Adjusted for local DVWA instance
    check_default_credentials(base_url, 'login.php')
