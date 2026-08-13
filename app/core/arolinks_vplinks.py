from urllib.parse import urlparse, unquote
from fastapi import Request

def is_arolinks_or_vplinks_url(url_str: str) -> bool:
    """Check if a URL string belongs to arolinks or vplinks (including subdomains)"""
    if not url_str:
        return False
    url_lower = url_str.lower()
    return (
        "arolink" in url_lower or
        "vplink" in url_lower or
        "arolinks" in url_lower or
        "vplinks" in url_lower
    )

def is_arolinks_or_vplinks_request(shortener_base_url: str = None, referer: str = None, user_shorteners: list = None) -> bool:
    """Pre-determine if a request or link is connected to Arolinks or Vplinks"""
    if shortener_base_url and is_arolinks_or_vplinks_url(shortener_base_url):
        return True
    if referer and is_arolinks_or_vplinks_url(referer):
        return True
    if user_shorteners:
        for s in user_shorteners:
            base_url = s.get("base_url")
            if base_url and is_arolinks_or_vplinks_url(base_url):
                return True
    return False

def detect_arolinks_vplinks_bypass(request: Request) -> tuple[bool, str]:
    """
    Rigorously detect userscript bypassers for Arolinks and Vplinks.
    Allows absolute URLs in query parameters (which are normal for manual redirections),
    but strictly blocks known bypasser keywords, script inject indicators, and tamper patterns.
    """
    referer = request.headers.get("referer", "")
    referer_decoded = unquote(referer).lower()

    # Banned keywords that indicate a bypasser
    banned_keywords = [
        "564048",
        "greasyfork",
        "tampermonkey",
        "stealth final",
        "github.com",
        "nicktrick",
        "smart nicktrick"
    ]

    # Check Referer for banned keywords
    for kw in banned_keywords:
        if kw in referer_decoded:
            return True, f"Banned userscript pattern '{kw}' detected in Arolinks/Vplinks Referer"

    # Check query parameters for banned keywords (excluding absolute URLs)
    for k, v in request.query_params.items():
        k_dec = unquote(k).lower()
        v_dec = unquote(v).lower()

        for kw in banned_keywords:
            if kw in k_dec or kw in v_dec:
                return True, f"Banned userscript pattern '{kw}' detected in Arolinks/Vplinks query parameters"

        # Check for direct key containing "bypass" if it's not a legitimate key
        if "bypass" in k_dec:
            return True, "Banned query parameter 'bypass' detected in Arolinks/Vplinks"

    return False, ""
