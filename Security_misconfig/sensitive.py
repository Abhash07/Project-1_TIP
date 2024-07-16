import requests

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
        response = session.get(base_url + file)
        if response.status_code == 200:
            print(f"Sensitive file accessible: {base_url}{file}")
        else:
            print(f"Sensitive file not accessible: {base_url}{file}")

# Example usage
if __name__ == "__main__":
    session = requests.Session()
    base_url = "http://127.0.0.1/DVWA/"  # Adjusted for local DVWA instance
    check_sensitive_files(session, base_url)
