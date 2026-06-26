import requests

def run_tech(target: str):
    try:
        r = requests.get(f"http://{target}", timeout=5)
        server = r.headers.get("Server", "unknown")

        tech = []

        if "nginx" in server.lower():
            tech.append("nginx")
        if "apache" in server.lower():
            tech.append("apache")

        return {
            "server": server,
            "detected": tech
        }

    except:
        return {
            "server": "unknown",
            "detected": []
        }
