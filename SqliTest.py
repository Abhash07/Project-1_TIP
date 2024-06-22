import requests
import time
import json

# Configuration
sqlmap_url = 'http://localhost:8775'
target_url = 'http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#'  # Adjust this URL based on your DVWA setup

# Function to start SQLmap scan
def start_sqlmap_scan(target):
    response = requests.post(f'{sqlmap_url}/task/new')
    task_id = response.json()['taskid']
    
    data = {
        'url': target,
        'data': "id=1&Submit=Submit",
        'method': 'GET',
        'level': 3,
        'risk': 2,
        'batch': True
    }
    
    response = requests.post(f'{sqlmap_url}/scan/{task_id}/start', json=data)
    return task_id

# Function to check SQLmap scan status
def check_sqlmap_status(task_id):
    response = requests.get(f'{sqlmap_url}/scan/{task_id}/status')
    return response.json()['status']

# Function to get SQLmap scan results
def get_sqlmap_results(task_id):
    response = requests.get(f'{sqlmap_url}/scan/{task_id}/data')
    return response.json()

# Main function
def main():
    # Start SQLmap scan
    print("Starting SQLmap scan...")
    sqlmap_task_id = start_sqlmap_scan(target_url)

    # Wait for SQLmap scan to complete
    while check_sqlmap_status(sqlmap_task_id) != 'terminated':
        print("SQLmap scan in progress...")
        time.sleep(10)
    
    print("SQLmap scan completed!")
    sqlmap_results = get_sqlmap_results(sqlmap_task_id)
    print("SQLmap Results:")
    print(json.dumps(sqlmap_results, indent=4))

if __name__ == "__main__":
    main()
