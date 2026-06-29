# modules/subdomains.py

import socket

COMMON = [
    "www",
    "api",
    "dev",
    "test",
    "mail",
    "admin",
    "portal",
    "app"
]

def run_subdomains(target: str):
    found = []

    for sub in COMMON:
        domain = f"{sub}.{target}"
        try:
            socket.gethostbyname(domain)
            found.append(domain)
        except:
            pass

    return found
