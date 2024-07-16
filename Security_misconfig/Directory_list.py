import requests

def check_directory_listing(base_url):
    directories = [
        base_url,
        base_url + 'images/',
        base_url + 'uploads/',
        base_url + 'files/',
        base_url + 'backup/'
    ]
    for directory in directories:
        response = requests.get(directory)
        if "Index of" in response.text:
            print(f"Directory listing enabled at {directory}")
        else:
            print(f"Directory listing not enabled at {directory}")

# Example usage
if __name__ == "__main__":
    base_url = "http://127.0.0.1/dvwa/"  # Adjusted for local DVWA instance
    check_directory_listing(base_url)
