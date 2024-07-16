import socket
import subprocess

def basic_socket_scan(host, port_range=(1, 1024), timeout=1):
    open_ports = []
    for port in range(port_range[0], port_range[1] + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    
    return open_ports

def nmap_scan(host, port_range="1-1024"):
    open_ports = []
    try:
        result = subprocess.run(['nmap', '-p', port_range, host], capture_output=True, text=True)
        output = result.stdout
        
        for line in output.split('\n'):
            if "/tcp" in line and "open" in line:
                port = int(line.split('/')[0])
                open_ports.append(port)
    except Exception as e:
        print(f"An error occurred while running nmap: {e}")
    
    return open_ports

def check_open_ports(host, port_range=(1, 1024)):
    print("Running basic socket scan...")
    socket_open_ports = basic_socket_scan(host, port_range)
    
    print("Running nmap scan...")
    nmap_open_ports = nmap_scan(host, f"{port_range[0]}-{port_range[1]}")
    
    all_open_ports = set(socket_open_ports + nmap_open_ports)
    
    if all_open_ports:
        print(f"Open ports on {host}: {sorted(all_open_ports)}")
    else:
        print(f"No open ports found on {host} in the range {port_range}")



# Example usage
if __name__ == "__main__":
    host = "http://127.0.0.1/DVWA/"  # Adjusted for local DVWA instance
    check_open_ports(host)
