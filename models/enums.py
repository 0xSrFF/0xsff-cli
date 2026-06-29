from enum import Enum

class AssetType(str, Enum):
    DOMAIN = "domain"
    HOST = "host"
    IP = "ip"
    PORT = "port"
    URL = "url"
    CERTIFICATE = "certificate"
    REPOSITORY = "repository"
    CLOUD_BUCKET = "cloud_bucket"

class RiskLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
