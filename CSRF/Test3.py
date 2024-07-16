import requests
import threading
import time
import warnings
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from colorama import Fore

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

def login_dvwa(session, url, username, password):
    login_url = urljoin(url, 'login.php')
    login_data = {
        'username': username,
        'password': password,
        'Login': 'Login'
    }
    response = session.post(login_url, data=login_data)
    if "login" in response.url:
        print(f"{Fore.RED}[CONSOLE] Login failed. Check credentials.")
    else:
        print(f"{Fore.GREEN}[CONSOLE] Login successful.")

def get_all_forms(url):
    r = s.get(url)
    soup = BeautifulSoup(r.content, "lxml")
    return soup.find_all("form")

def get_details(form):
    details = {}
    try:
        act = form.attrs.get("action").lower()
    except:
        act = None

    method = form.attrs.get("method", "get").lower()
    
    inputs = []
    for tag in form.find_all("input"):
        input_type = tag.attrs.get("type", "text")
        input_value = tag.attrs.get("value", "")
        input_name = tag.attrs.get("name")
        inputs.append({"type": input_type, "value": input_value, "name": input_name})
    details["method"] = method
    details["action"] = act
    details["inputs"] = inputs
    return details

def test_csrf_form(url, form_details):
    for scenario in csrf_scenarios:
        data = {}
        for tag in form_details['inputs']:
            if tag["name"] in scenario:
                data[tag["name"]] = scenario[tag["name"]]
            elif tag["type"] == "hidden" or tag["value"]:
                data[tag["name"]] = tag["value"]
        form_url = urljoin(url, form_details["action"])
        if form_details["method"] == "post":
            response = s.post(form_url, data=data)
        elif form_details["method"] == "get":
            response = s.get(form_url, params=data)
        print(f"{Fore.GREEN}Testing CSRF with parameters: {data}")
        print(f"{Fore.WHITE}Response: {response.text}")

def scan_csrf(url):
    forms = get_all_forms(url)
    print(f"{Fore.CYAN}[CONSOLE] Detected {len(forms)} forms on {url}")
    for form in forms:
        form_details = get_details(form)
        test_csrf_form(url, form_details)

def start_scan():
    global checked
    try:
        threads = []
        with open('urls.txt', 'r') as f:
            urls = f.readlines()
            for url in urls:
                t = threading.Thread(target=scan_csrf, args=(url.strip(),))
                t.start()
                threads.append(t)
                time.sleep(0.1)  # Small delay to avoid overwhelming the server

            for t in threads:
                t.join()
    except FileNotFoundError:
        print(f"{Fore.RED}[CONSOLE] Please create 'urls.txt' and add the URLs to it.")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[CONSOLE] Request exception: {e}")

def start_csrf_scan():
    global s
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')

    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36"

    # Disable SSL verification warnings
    s.verify = False

    # Login to DVWA
    dvwa_url = 'http://127.0.0.1/DVWA/'
    dvwa_username = 'admin'
    dvwa_password = 'password'
    login_dvwa(s, dvwa_url, dvwa_username, dvwa_password)

    start_scan()

# Start the CSRF scan process
start_csrf_scan()
