import socket

COMMON_PORTS = [80, 443, 22, 21, 25, 110, 3306, 8080]

def run_ports(target: str):
    open_ports = []

    for port in COMMON_PORTS:
        s = socket.socket()
        s.settimeout(1)

        try:
            s.connect((target, port))
            open_ports.append(port)
            s.close()
        except:
            pass

    return open_ports
