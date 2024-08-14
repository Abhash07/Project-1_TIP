import tkinter as tk
from dvwa_session import login_dvwa, set_security_level, base_url, user_username, user_password

auth_bypass_url = base_url + "vulnerabilities/authbypass/"
get_user_data_url = base_url + "vulnerabilities/authbypass/get_user_data.php"
change_user_details_url = base_url + "vulnerabilities/authbypass/change_user_details.php"

# Function to manually check if a page can be accessed (Low Level)
def check_access_low(session):
    response = session.get(auth_bypass_url)
    result = {
        "status": "Successful" if "Unauthorised" not in response.text and response.status_code == 200 else "Failed",
        "test_performed": "Direct access to /vulnerabilities/authbypass/ as a non-admin user.",
        "output_snippet": response.text[:500],  # Show first 500 characters of the response
        "status_code": response.status_code,
        "explanation": ""
    }
    if result["status"] == "Successful":
        result["explanation"] = ("This test was successful because the application did not enforce proper access controls. "
                                 "As a result, a non-admin user could directly access sensitive pages. This indicates a vulnerability "
                                 "wherein proper authorization checks are missing or insufficient.")
    else:
        result["explanation"] = ("This test failed because the application correctly enforced access controls. "
                                 "Non-admin users were not able to access pages that require higher privileges, indicating that "
                                 "proper access control mechanisms are in place.")
    return result

# Function to check API access (Medium Level)
def check_access_medium(session):
    response = session.get(get_user_data_url)
    result = {
        "status": "Successful" if "Access denied" not in response.text and response.status_code == 200 else "Failed",
        "test_performed": "Direct access to /vulnerabilities/authbypass/get_user_data.php as a non-admin user.",
        "output_snippet": response.text[:500],  # Show first 500 characters of the response
        "status_code": response.status_code,
        "explanation": ""
    }
    if result["status"] == "Successful":
        result["explanation"] = ("This test was successful because the application exposed API endpoints without proper access controls. "
                                 "A non-admin user was able to retrieve sensitive user data, indicating that the application "
                                 "lacks proper access control mechanisms for its APIs.")
    else:
        result["explanation"] = ("This test failed because the application correctly enforced access controls on the API. "
                                 "Non-admin users were denied access to sensitive data, demonstrating that the API is protected "
                                 "with proper authorization checks.")
    return result

# Function to modify data (High Level)
def check_access_high(session):
    payload = {'id': 1, "first_name": "Harry", "surname": "Hacker"}
    headers = {'Content-Type': 'application/json'}
    response = session.post(change_user_details_url, json=payload, headers=headers)
    result = {
        "status": "Successful" if "Access denied" not in response.text and response.status_code == 200 else "Failed",
        "test_performed": "POST request to /vulnerabilities/authbypass/change_user_details.php to modify user details as a non-admin user.",
        "output_snippet": response.text[:500],  # Show first 500 characters of the response
        "status_code": response.status_code,
        "explanation": ""
    }
    if result["status"] == "Successful":
        result["explanation"] = ("This test was successful because the application allowed a non-admin user to modify sensitive data. "
                                 "This indicates a lack of proper authorization checks in the application’s business logic, "
                                 "allowing unauthorized users to perform privileged actions.")
    else:
        result["explanation"] = ("This test failed because the application correctly enforced access controls on data modification. "
                                 "Non-admin users were unable to change sensitive information, indicating that the application’s "
                                 "business logic includes proper authorization checks.")
    return result

# Function to test Missing Function-Level Access Control (e.g., delete a user)
def test_function_level_access_control(session):
    delete_user_url = base_url + "vulnerabilities/admin/delete_user.php?user_id=2"
    response = session.get(delete_user_url)
    result = {
        "status": "Successful" if "Unauthorised" not in response.text and response.status_code == 200 else "Failed",
        "test_performed": "Direct access to /vulnerabilities/admin/delete_user.php to delete a user as a non-admin user.",
        "output_snippet": response.text[:500],  # Show first 500 characters of the response
        "status_code": response.status_code,
        "explanation": ""
    }
    if result["status"] == "Successful":
        result["explanation"] = ("This test was successful because the application allowed a non-admin user to perform admin-level actions, "
                                 "such as deleting a user. This indicates a severe lack of function-level access control, "
                                 "which should restrict such actions to authorized users only.")
    else:
        result["explanation"] = ("This test failed because the application correctly enforced function-level access controls. "
                                 "Non-admin users were prevented from performing admin-level actions, showing that the application "
                                 "is properly secured against unauthorized access.")
    return result

# Function to test for Path Traversal
def test_path_traversal(session):
    traversal_url = base_url + "vulnerabilities/upload/files/../../../../etc/passwd"
    response = session.get(traversal_url)
    result = {
        "status": "Successful" if "No such file or directory" not in response.text and response.status_code == 200 else "Failed",
        "test_performed": "Path traversal attempt to access /etc/passwd via /vulnerabilities/upload/files/.",
        "output_snippet": response.text[:500],  # Show first 500 characters of the response
        "status_code": response.status_code,
        "explanation": ""
    }
    if result["status"] == "Successful":
        result["explanation"] = ("This test was successful because the application was vulnerable to path traversal attacks. "
                                 "This allowed access to sensitive files, such as /etc/passwd, which should not be accessible to users. "
                                 "The vulnerability exists because the application does not properly validate or sanitize user inputs.")
    else:
        result["explanation"] = ("This test failed because the application correctly handled the path traversal attempt. "
                                 "It either sanitized the user input or implemented proper validation to prevent access to unauthorized directories.")
    return result

# Function to test CSRF by omitting token
def test_csrf(session):
    payload = {'id': 1, "first_name": "Harry", "surname": "Hacker"}
    headers = {'Content-Type': 'application/json'}
    response = session.post(change_user_details_url, json=payload, headers=headers)
    result = {
        "status": "Successful" if "Access denied" not in response.text and response.status_code == 200 else "Failed",
        "test_performed": "POST request to /vulnerabilities/authbypass/change_user_details.php to modify user details without CSRF token.",
        "output_snippet": response.text[:500],  # Show first 500 characters of the response
        "status_code": response.status_code,
        "explanation": ""
    }
    if result["status"] == "Successful":
        result["explanation"] = ("This test was successful because the application did not enforce CSRF protection. "
                                 "As a result, an attacker could perform actions on behalf of an authenticated user, "
                                 "leading to unauthorized operations being performed.")
    else:
        result["explanation"] = ("This test failed because the application enforced CSRF protection. "
                                 "The request was denied due to the missing CSRF token, which indicates that the application "
                                 "is protected against such attacks.")
    return result

# Function to run the tests and update the output in the UI
def run_tests(text_area, security_level):
    text_area.delete('1.0', tk.END)
    text_area.insert(tk.END, "Performing tests, please wait...\n", "Info")
    text_area.update()

    session = login_dvwa(user_username, user_password)
    if session:
        session = set_security_level(session, security_level)

        # Dictionary to store the results of each test
        test_results = {
            "Low-Level Access (Forced Browsing)": check_access_low(session),
            "Medium-Level Access (IDOR)": check_access_medium(session),
            "High-Level Access (Function-Level Access Control)": check_access_high(session),
            "Missing Function-Level Access Control": test_function_level_access_control(session),
            "Path Traversal": test_path_traversal(session),
            "CSRF": test_csrf(session)
        }

        # Configure tag colors
        text_area.tag_configure("Success", foreground="green")
        text_area.tag_configure("Fail", foreground="red")
        text_area.tag_configure("Bold", font=("Helvetica", 10, "bold"))
        text_area.tag_configure("Title", font=("Helvetica", 12, "bold"))
        text_area.tag_configure("Info", foreground="blue", font=("Helvetica", 10, "italic"))

        # Display the results with explanations
        text_area.delete('1.0', tk.END)
        for test, result in test_results.items():
            tag = "Success" if result['status'] == "Successful" else "Fail"

            text_area.insert(tk.END, f"Test: {test}\n", "Title")
            text_area.insert(tk.END, f"Status: ", "Bold")
            text_area.insert(tk.END, f"{result['status']}\n", tag)
            text_area.insert(tk.END, f"Test Performed: {result['test_performed']}\n", "Bold")
            text_area.insert(tk.END, f"Output Snippet: {result['output_snippet']}\n", "Bold")
            text_area.insert(tk.END, f"Status Code: {result['status_code']}\n\n", "Bold")
            text_area.insert(tk.END, f"Conclusion: {result['explanation']}\n\n", "Bold")

        # Final analysis
        if all(result["status"] == "Failed" for result in test_results.values()):
            text_area.insert(tk.END, "No Broken Access Control vulnerabilities found.\n", "Fail")
        else:
            text_area.insert(tk.END, "Some Broken Access Control vulnerabilities were detected.\n", "Success")
    else:
        text_area.delete('1.0', tk.END)
        text_area.insert(tk.END, "Login failed. Cannot perform tests.", "Fail")
