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
    Rigorously detect userscript bypassers for Arolinks and Vplinks without
    falsely flagging legitimate user redirections.
    Allows absolute URLs and standard query parameters, but blocks explicit userscript
    script files (e.g. .user.js) and script managers in Referer.
    """
    referer = request.headers.get("referer", "")
    referer_decoded = unquote(referer).lower()

    # Banned userscript indicators (specific to script files and userscript managers)
    banned_referer_keywords = [
        "564048",
        "greasyfork.org/scripts",
        "tampermonkey",
        "stealth final",
        ".user.js"
    ]

    for kw in banned_referer_keywords:
        if kw in referer_decoded:
            return True, f"Banned userscript pattern '{kw}' detected in Arolinks/Vplinks Referer"

    # Check query parameters for explicit userscript URLs or script installer patterns
    for k, v in request.query_params.items():
        k_dec = unquote(k).lower()
        v_dec = unquote(v).lower()

        if "greasyfork.org/scripts" in v_dec or ".user.js" in v_dec:
            return True, f"Banned userscript pattern detected in Arolinks/Vplinks query parameters"

    return False, ""
