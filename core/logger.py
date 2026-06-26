from datetime import datetime

# ANSI Color Codes
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def log(message, level="INFO"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    # Color coding based on message content
    if "[+]" in message:
        print(f"{Colors.GREEN}[{timestamp}] {message}{Colors.ENDC}")
    elif "[!]" in message or "[*]" in message:
        print(f"{Colors.CYAN}[{timestamp}] {message}{Colors.ENDC}")
    elif "HIGH" in message or "CRITICAL" in message:
        print(f"{Colors.FAIL}{Colors.BOLD}{message}{Colors.ENDC}")
    elif "MEDIUM" in message:
        print(f"{Colors.WARNING}{message}{Colors.ENDC}")
    elif "LOW" in message:
        print(f"{Colors.BLUE}{message}{Colors.ENDC}")
    else:
        print(f"{message}")
