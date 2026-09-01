import os
from functools import lru_cache

TEMPLATES_DIR = os.path.dirname(os.path.abspath(__file__))

@lru_cache(maxsize=16)
def load_template(filename: str) -> str:
    """Read HTML template file and cache its content in memory."""
    filepath = os.path.join(TEMPLATES_DIR, filename)
    with open(filepath, "r", encoding="utf-8") as f:
        return f.read()

def render_template(filename: str, **context) -> str:
    """Load template and replace placeholder variables."""
    content = load_template(filename)
    for key, value in context.items():
        content = content.replace(f"{{{key}}}", str(value))
    return content
