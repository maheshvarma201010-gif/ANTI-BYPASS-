from urllib.parse import urlparse

def is_arolinks_or_vplinks_url(url_str: str) -> bool:
    """Check if a URL string belongs to arolinks or vplinks"""
    if not url_str:
        return False
    url_lower = url_str.lower()
    return "arolinks" in url_lower or "vplinks" in url_lower

def is_arolinks_or_vplinks_request(shortener_base_url: str = None, referer: str = None) -> bool:
    """Pre-determine if a request or link is connected to Arolinks or Vplinks"""
    if shortener_base_url and is_arolinks_or_vplinks_url(shortener_base_url):
        return True
    if referer and is_arolinks_or_vplinks_url(referer):
        return True
    return False
