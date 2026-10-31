"""Explicit crawl, response-size and timing defaults; documented in README.md."""
from dataclasses import dataclass

SCHEMA_VERSION = "c2.check.v0.4-draft"
EXTENDED_SCHEMA_VERSION = "layerly.check.v0.5-draft"
USER_AGENT = "LayerlySiteCheck/0.2"
ROBOTS_PRODUCT_TOKEN = "layerlysitecheck"  # matched case-insensitively in robots.txt


@dataclass(frozen=True)
class Limits:
    max_pages: int = 5
    max_requests: int = 20          # every HTTP attempt: robots, page, redirect hop, HEAD/GET, retry
    max_dns_lookups: int = 30       # separate counter, cached per job
    max_redirects: int = 5          # hops per chain
    connect_timeout_s: float = 5.0
    request_timeout_s: float = 10.0
    job_timeout_s: float = 60.0
    max_body_bytes: int = 2 * 1024 * 1024    # after decompression
    max_robots_bytes: int = 512 * 1024
    min_host_interval_s: float = 0.5
    max_url_length: int = 2048
    excerpt_chars: int = 300
    max_retries: int = 1            # only for connection_failed, never for timeout
    low_text_chars: int = 250       # content.low_text heuristic threshold
    title_min_chars: int = 10
    title_max_chars: int = 70


PAGE_CONTENT_TYPES = ("text/html", "application/xhtml+xml")
NON_HTML_EXTENSIONS = (
    ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".zip", ".rar", ".gz",
    ".mp4", ".mp3", ".avi", ".mov", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".css", ".js", ".json", ".xml", ".txt", ".ico", ".woff", ".woff2", ".ttf",
)
TRACKING_PARAMS = ("utm_", "gclid", "fbclid", "mc_cid", "mc_eid", "yclid", "msclkid")
