# DVWA Vulnerability Testing Toolkit

## Overview
This toolkit is designed to automate the process of testing for various vulnerabilities in the Damn Vulnerable Web Application (DVWA). It provides a user-friendly interface to run tests for SQL Injection, Command Injection, and Broken Access Control vulnerabilities across different security levels.

## Features
- Graphical User Interface for easy test selection and execution
- Support for multiple vulnerability types:
  - SQL Injection (SQLI)
  - Command Injection (CI)
  - Broken Access Control (BAC)
- Ability to test against different DVWA security levels (Low, Medium, High, Impossible)
- Real-time display of test results
- Modular design for easy expansion and maintenance

## Prerequisites
- Python 3.x
- DVWA set up and running
- Required Python libraries: tkinter, requests, beautifulsoup4

## Installation
1. Clone this repository:
   ```
   git clone [https://github.com/your-username/dvwa-vulnerability-testing-toolkit.git](https://github.com/Abhash07/
   ```
2. Install required dependencies:
   ```
   pip install requests beautifulsoup4
   ```

## Usage
1. Run the main script:
   ```
   python main.py
   ```
2. Use the GUI to select the type of test and the DVWA security level.
3. Click "Run Selected Test" to start the vulnerability scan.
4. View the results in the scrollable text area.

## File Structure
- `main.py`: The main application script with the GUI
- `sqli_test.py`: SQL Injection testing module
- `ci_test.py`: Command Injection testing module
- `bac_test.py`: Broken Access Control testing module
- `dvwa_session.py`: Handles DVWA authentication and session management
- `payload_loader.py`: Loads payloads from text files
- `sqlipayloads.txt`: Contains SQL Injection payloads
- `cipayloads.txt`: Contains Command Injection payloads

## Configuration
Ensure that the `base_url`, `dvwa_username`, and `dvwa_password` in `dvwa_session.py` are correctly set to match your DVWA installation.

## Disclaimer
This tool is for educational purposes only. Only use it on applications you have permission to test. The authors are not responsible for any misuse or damage caused by this program.

## Contribution
Contributions to improve the toolkit are welcome. Please feel free to submit pull requests or create issues for bugs and feature requests.


