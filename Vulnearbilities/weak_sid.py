import requests
import hashlib

def test_weak_session_ids(session, base_url, iterations=100):
    endpoint = 'vulnerabilities/weak_id/'
    session_ids = set()

    for _ in range(iterations):
        response = session.get(base_url + endpoint)
        if 'dvwaSession' in session.cookies:
            session_id = session.cookies['dvwaSession']
            session_ids.add(session_id)
    
    if len(session_ids) < iterations:
        print("Weak Session ID vulnerability detected. Duplicate session IDs found.")
    else:
        print("No Weak Session ID vulnerability detected. All session IDs are unique.")

    #print("Generated session IDs:")
    #for session_id in session_ids:
     #   print(session_id)

# Example usage
if __name__ == "__main__":
    session = requests.Session()
    base_url = "http://127.0.0.1/DVWA/"  # Adjusted for local DVWA instance
    test_weak_session_ids(session, base_url)
