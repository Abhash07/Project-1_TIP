import tkinter as tk
from dvwa_session import login_dvwa, set_security_level, base_url
from payload_loader import load_payloads

sqli_url = base_url + "vulnerabilities/sqli/?id="

# Function to test each payload for SQL Injection
def test_payloads(session, payloads, text_area):
    vulnerable_payloads = []
    try:
        for payload in payloads:
            full_url = f"{sqli_url}1{payload}&Submit=Submit"
            response = session.get(full_url)
            text_area.insert(tk.END, f"Testing payload: {payload}\n", "Info")
            text_area.update()
            
            if response.status_code == 500 or "you have an error in your sql syntax" in response.text.lower() or \
               "warning" in response.text.lower() or "mysql_fetch" in response.text.lower() or \
               "mysql_num_rows" in response.text.lower() or "syntax error" in response.text.lower() or \
               "unclosed quotation mark" in response.text.lower() or "quoted string not properly terminated" in response.text.lower() or \
               "sql syntax" in response.text.lower():
                vulnerable_payloads.append(payload)
                text_area.insert(tk.END, f"Success: {payload}\n", "Success")
            else:
                text_area.insert(tk.END, f"Failed: {payload}\n", "Fail")

            text_area.see(tk.END)  # Auto-scroll down to the latest result
            text_area.update()
    except Exception as e:
        text_area.insert(tk.END, f"Error during payload testing: {e}\n", "Fail")
    return vulnerable_payloads

# Function to run the tests and update the output in the UI
def launch_attack(text_area, security_level):
    text_area.delete('1.0', tk.END)
    text_area.insert(tk.END, "Performing SQL Injection tests, please wait...\n", "Info")
    text_area.update()
    
    session = login_dvwa()
    
    if session:
        session = set_security_level(session, security_level)
        
        payloads = load_payloads("sqlipayloads.txt")
        vulnerable_payloads = test_payloads(session, payloads, text_area)
        
        text_area.tag_configure("Success", foreground="green", font=("Helvetica", 10, "bold"))
        text_area.tag_configure("Fail", foreground="red", font=("Helvetica", 10, "bold"))
        text_area.tag_configure("Bold", font=("Helvetica", 10, "bold"))
        text_area.tag_configure("Title", font=("Helvetica", 12, "bold"))
        text_area.tag_configure("Info", foreground="blue", font=("Helvetica", 10, "italic"))

        text_area.insert(tk.END, "\n--- Test Summary ---\n", "Title")
        if vulnerable_payloads:
            text_area.insert(tk.END, "SQL Injection vulnerabilities found with the following payloads:\n", "Bold")
            for payload in vulnerable_payloads:
                text_area.insert(tk.END, f"- {payload}\n", "Success")
        else:
            text_area.insert(tk.END, "No SQL Injection vulnerabilities found.\n", "Fail")
    else:
        text_area.delete('1.0', tk.END)
        text_area.insert(tk.END, "Login failed. Cannot perform tests.", "Fail")
