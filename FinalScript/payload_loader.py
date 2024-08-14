def load_payloads(filepath):
    payloads = []
    try:
        with open(filepath, 'r') as file:
            payloads = [line.strip() for line in file if line.strip()]
    except Exception as e:
        print(f"Error loading payloads from {filepath}: {e}")
    return payloads

def load_category_payloads(filepath):
    payloads = {}
    current_category = None
    try:
        with open(filepath, 'r') as file:
            for line in file:
                line = line.strip()
                if line.startswith("#"):
                    current_category = line.split("#")[1].strip()
                    payloads[current_category] = []
                elif line and current_category:
                    payloads[current_category].append(line)
    except Exception as e:
        print(f"Error loading payloads: {e}")
    return payloads
