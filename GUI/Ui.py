import tkinter as tk
from tkinter import scrolledtext
import subprocess
import threading
import os

def start_attack():
    def run_attack():
        script_path = os.path.join('Vuln', 'main.py')
        process = subprocess.Popen(['python', script_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in process.stdout: # type: ignore
            log_text.insert(tk.END, line)
        for line in process.stderr: # type: ignore
            log_text.insert(tk.END, line)
    
    log_window = tk.Toplevel(root)
    log_window.title("Attack Logs")
    log_text = scrolledtext.ScrolledText(log_window, wrap=tk.WORD, width=100, height=30)
    log_text.pack(fill=tk.BOTH, expand=True)

    threading.Thread(target=run_attack).start()

root = tk.Tk()
root.title("Backdoor Tool")
root.geometry("600x400")

frame = tk.Frame(root, bg="black")
frame.pack(fill=tk.BOTH, expand=True)

title_label = tk.Label(frame, text="Welcome to the Backdoor Tool", font=("Helvetica", 16, "bold"), bg="black", fg="white")
title_label.pack(pady=20)

desc_label = tk.Label(frame, text="This is an automated attack tool. With the help of a simple button you can exploit vulnerabilities", font=("Helvetica", 12), bg="black", fg="white")
desc_label.pack(pady=10)

start_button = tk.Button(frame, text="Start Attack", font=("Helvetica", 14), command=start_attack)
start_button.pack(pady=20)

root.mainloop()
