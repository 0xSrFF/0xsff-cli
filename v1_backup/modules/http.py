# modules/http.py

import requests
from bs4 import BeautifulSoup

def run_http(target: str):
    url = f"http://{target}"

    try:
        r = requests.get(url, timeout=5)

        title = None
        try:
            soup = BeautifulSoup(r.text, "html.parser")
            title = soup.title.string.strip() if soup.title else None
        except:
            pass

        return {
            "url": url,
            "status": r.status_code,
            "title": title
        }

    except:
        return {
            "url": url,
            "status": "DOWN",
            "title": None
        }
