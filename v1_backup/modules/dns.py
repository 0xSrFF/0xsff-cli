# modules/dns.py

import dns.resolver

def run_dns(target: str):
    results = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "TXT": [],
        "NS": []
    }

    record_types = ["A", "AAAA", "MX", "TXT", "NS"]

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(target, rtype)
            for r in answers:
                results[rtype].append(str(r))
        except:
            pass

    return results
