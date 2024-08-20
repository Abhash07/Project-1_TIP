import requests

def check_security_headers(url):
    response = requests.get(url)
    headers = response.headers

    required_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection"
    ]

    missing_headers = [header for header in required_headers if header not in headers]

    if missing_headers:
        print(f"Missing security headers at {url}: {missing_headers}")
    else:
        print(f"All required security headers are present at {url}")

def check_https_enforcement(url):
    if not url.startswith("https://"):
        print(f"URL does not use HTTPS: {url}")
        return

    try:
        response = requests.get(url, allow_redirects=False)
        if response.status_code in [301, 302] and "Location" in response.headers:
            location = response.headers["Location"]
            if location.startswith("http://"):
                print(f"Redirects to insecure HTTP from {url} to {location}")
            else:
                print(f"HTTPS is enforced at {url}")
        else:
            print(f"HTTPS is enforced at {url}")
    except Exception as e:
        print(f"An error occurred while checking HTTPS enforcement at {url}: {e}")

# Example usage
if __name__ == "__main__":
    url = "http://127.0.0.1/dvwa/"  # Adjusted for local DVWA instance
    check_security_headers(url)
    check_https_enforcement(url)

