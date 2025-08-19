import re

def is_valid_hostname(hostname: str) -> bool:
    """
    Validate hostname format
    """
    # Basic hostname validation - adjust as needed
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(pattern, hostname)) and len(hostname) <= 253