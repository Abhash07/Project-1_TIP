import requests

def check_error_handling(base_url):
    error_triggers = [
        'non_existent_page',
        'invalid_path',
        'cause_error',
        'trigger_error',
        '404',
        '500'
    ]
    for trigger in error_triggers:
        response = requests.get(base_url + trigger)
        if response.status_code == 500 or "error" in response.text.lower():
            print(f"Detailed error message exposed at {base_url}{trigger}")
        else:
            print(f"No detailed error message exposed at {base_url}{trigger}")

# Example usage
if __name__ == "__main__":
    base_url = "http://127.0.0.1/dvwa/"  # Adjusted for local DVWA instance
    check_error_handling(base_url)
