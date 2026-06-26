import os
import yaml
from core.logger import log

DEFAULT_CONFIG = {
    "github_token": "",
    "scan_timeout": 10,
    "max_subdomains": 100,
    "risk_thresholds": {
        "high_score": 8,
        "critical_score": 9
    },
    "output": {
        "verbose": False,
        "colorize": True
    }
}

def load_config():
    config_path = "config.yaml"
    if not os.path.exists(config_path):
        log("[*] No config.yaml found. Creating default...")
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG
    
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        # Merge with defaults to ensure all keys exist
        for key, value in DEFAULT_CONFIG.items():
            if key not in config:
                config[key] = value
        return config
    except Exception as e:
        log(f"[!] Error loading config: {e}. Using defaults.")
        return DEFAULT_CONFIG

def save_config(config):
    with open("config.yaml", 'w') as f:
        yaml.dump(config, f, default_flow_style=False)
