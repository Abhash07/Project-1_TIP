import tkinter as tk
from tkinter import messagebox, scrolledtext
from ci_test import launch_attack as ci_launch_attack
from sqli_test import launch_attack as sqli_launch_attack
from bac_test import run_tests as bac_run_tests

# Create the main window
root = tk.Tk()
root.title("DVWA Vulnerability Test Launcher")

# Create a scrolled text area to display the output
text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=30)
text_area.pack(pady=10)

# Create a StringVar to store the selected test and security level
selected_test = tk.StringVar(value="ci")
selected_security_level = tk.StringVar(value="low")

# Function to run the selected test
def run_selected_test():
    test = selected_test.get()
    security_level = selected_security_level.get()

    if test == "ci":
        ci_launch_attack(text_area, security_level)
    elif test == "sqli":
        sqli_launch_attack(text_area, security_level)
    elif test == "bac":
        bac_run_tests(text_area, security_level)

# Create radio buttons to select the test
tk.Label(root, text="Select a Test to Run:").pack(pady=5)
tk.Radiobutton(root, text="Command Injection", variable=selected_test, value="ci").pack(anchor=tk.W)
tk.Radiobutton(root, text="SQL Injection", variable=selected_test, value="sqli").pack(anchor=tk.W)
tk.Radiobutton(root, text="Broken Access Control", variable=selected_test, value="bac").pack(anchor=tk.W)

# Create radio buttons to select the security level
tk.Label(root, text="Select DVWA Security Level:").pack(pady=5)
tk.Radiobutton(root, text="Low", variable=selected_security_level, value="low").pack(anchor=tk.W)
tk.Radiobutton(root, text="Medium", variable=selected_security_level, value="medium").pack(anchor=tk.W)
tk.Radiobutton(root, text="High", variable=selected_security_level, value="high").pack(anchor=tk.W)
tk.Radiobutton(root, text="Impossible", variable=selected_security_level, value="impossible").pack(anchor=tk.W)

# Create a button to launch the selected test
launch_button = tk.Button(root, text="Run Selected Test", command=run_selected_test)
launch_button.pack(pady=10)

def on_closing():
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        root.destroy()

root.protocol("WM_DELETE_WINDOW", on_closing)

# Run the main loop
root.mainloop()
