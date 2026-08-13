from fastapi import Request, HTTPException
from fastapi.responses import RedirectResponse
from urllib.parse import urlparse
import time
from bson import ObjectId

def is_arolinks_or_vplinks_url(url: str) -> bool:
    if not url:
        return False
    url_lower = url.lower()
    return "arolinks" in url_lower or "vplinks" in url_lower
