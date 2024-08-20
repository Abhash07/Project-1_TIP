Introduction
This manual provides comprehensive guidance on deploying, using, and maintaining the vulnerability testing tool. The tool is designed to identify potential CSRF, Security Misconfiguration, Command Injection and Open CSP vulnerabilities in web applications, particularly focusing on the Damn Vulnerable Web Application (DVWA). The tool is organized into various test cases, each addressing specific test scenarios, and is managed through a central `main.py` script that triggers these tests.

System Requirements

Operating System: Linux (preferred), macOS, or Windows with WSL
Python Version: Python 3.6 or higher
Dependencies: 
  - requests
  - beautifulsoup4

Web Application: Damn Vulnerable Web Application (DVWA), hosted locally or on a server
Network Access: Ensure that the tool has access to the DVWA instance, typically running on `http://127.0.0.1/DVWA/`

Deployment

 Step 1: Clone the Repository

First, clone the repository containing the  testing tool:

git clone https://github.com/Abhash07/Project-1_TIP.git
cd GUI


Step 2: Install Dependencies

Ensure that Python 3 is installed on your system. Install the required Python packages 
sudo apt-get install python3.6

Step 3: Configure DVWA

1. Download and set up DVWA from the official DVWA GitHub repository(digininja/DVWA: Damn Vulnerable Web Application (DVWA) (github.com)).
2. Ensure that DVWA is correctly configured and running locally or on a remote server.

Step 4: Edit Configuration
If necessary, edit the `base_url` variable in the `main.py` script to match the URL where your DVWA instance is hosted. By default, it is set to `http://127.0.0.1/DVWA/`.





 Usage

 Basic Setup

1. Ensure that DVWA is running and accessible.
2. Run the `UI.py` script from your terminal to begin testing:

Python3 UI.py

Running the Main Script

The `main.py` script is the central entry point for triggering all the test cases. It includes tests for various scenarios:

- Advanced CSRF Scenarios
- Privilege Escalation
- Command Injection
- Weak Session ID
- Open CSP
- Default Credentials
- Sensitive Files
- Sensitive Error Messages Exposure
- Buffer Overflow
- Open Ports
-  Missing Security Headers
- Directory Listing 

Each test case is a separate function within the script, and they are all executed sequentially and in real-time when you run `main.py`.


Maintenance

Updating the Tool

Periodically check for updates to the tool by pulling the latest changes from the repository:

git pull origin Sam_Final

 Troubleshooting

If you encounter issues while using the tool:

1. Check Dependencies: Ensure that all required Python packages are installed and up-to-date.
2. Verify DVWA Configuration: Make sure that DVWA is running with the correct security level and that it is accessible from the machine running the tool.
3. Error Messages: Review any error messages output by the script and consult relevant Python documentation or community forums for help.


 Conclusion	
This CSRF testing tool is a comprehensive resource for identifying and mitigating CSRF vulnerabilities in web applications. By following this manual, you can effectively deploy, use, and maintain the tool to ensure the security of your applications against CSRF attacks. Regular updates and testing will help keep your applications secure.
