"""URL syntax validation and normalisation (architecture component [2])."""
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, quote

from .errors import InputRejected

DEFAULT_PORTS = {"http": 80, "https": 443}
BLOCKED_HOSTNAMES = {
    "localhost", "metadata", "metadata.google.internal", "instance-data",
    "instance-data.ec2.internal", "metadata.azure.com",
}
BLOCKED_SUFFIXES = (
    ".localhost", ".local", ".internal", ".home.arpa", ".localdomain", ".lan",
    ".intranet", ".corp", ".private", ".test.internal",
)
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_NUMERIC_PART = re.compile(r"^(?:0x[0-9a-f]*|0[0-7]*|[1-9][0-9]*)$")
_PATH_SAFE = "/%:@!$&'()*+,;=-._~"


@dataclass(frozen=True)
class NormalizedURL:
    scheme: str
    host: str      # ASCII (punycode), lower case, no trailing dot
    port: int
    path: str      # path plus "?query" if any; never empty
    url: str

    @property
    def origin(self):
        return f"{self.scheme}://{self.host}" + ("" if DEFAULT_PORTS[self.scheme] == self.port else f":{self.port}")


def _looks_like_ipv4(host):
    """WHATWG-style: hosts like 2130706433, 0x7f.1, 017700000001 are IPv4 literals."""
    parts = host.split(".")
    if parts and parts[-1] == "":
        parts = parts[:-1]
    if not parts or len(parts) > 4:
        return bool(parts) and all(_NUMERIC_PART.match(p) for p in parts)
    if all(_NUMERIC_PART.match(p) for p in parts):
        return True
    # a final all-numeric label makes the host an (invalid) IPv4 for browsers
    return bool(re.fullmatch(r"[0-9]+", parts[-1]))


def normalize_url(raw, max_length=2048):
    if not isinstance(raw, str) or not raw.strip():
        raise InputRejected("invalid_url", "URL is empty.")
    raw = raw.strip()
    if len(raw) > max_length:
        raise InputRejected("url_too_long", f"URL is longer than {max_length} characters.")
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in raw):
        raise InputRejected("invalid_url", "URL contains whitespace or control characters.")
    if "\\" in raw:
        raise InputRejected("invalid_url", "URL contains a backslash.")
    try:
        parts = urlsplit(raw)
    except ValueError:
        raise InputRejected("invalid_url", "URL cannot be parsed.")
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise InputRejected("unsupported_scheme", "Only http and https are supported.")
    netloc = parts.netloc
    if not netloc:
        raise InputRejected("invalid_url", "URL has no host.")
    if "@" in netloc:
        raise InputRejected("credentials_in_url", "URLs with user names or passwords are not accepted.")
    if netloc.startswith("["):
        raise InputRejected("ip_literal_not_allowed", "Enter a domain name, not an IP address.")
    try:
        port = parts.port
    except ValueError:
        raise InputRejected("invalid_url", "Port is not valid.")
    if port is not None and port != DEFAULT_PORTS[scheme]:
        raise InputRejected("unsupported_port", "Only the default port is supported.")
    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise InputRejected("invalid_url", "URL has no host.")
    try:
        host = host.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        raise InputRejected("invalid_url", "Host name is not valid.")
    try:
        ipaddress.ip_address(host)
        raise InputRejected("ip_literal_not_allowed", "Enter a domain name, not an IP address.")
    except ValueError:
        pass
    if _looks_like_ipv4(host):
        raise InputRejected("ip_literal_not_allowed", "Enter a domain name, not an IP address.")
    if len(host) > 253 or not all(_LABEL.match(label) for label in host.split(".")):
        raise InputRejected("invalid_url", "Host name is not valid.")
    if "." not in host or host in BLOCKED_HOSTNAMES or host.endswith(BLOCKED_SUFFIXES):
        raise InputRejected("blocked_destination", "This address cannot be checked.")
    path = quote(parts.path or "/", safe=_PATH_SAFE)
    if parts.query:
        path += "?" + quote(parts.query, safe=_PATH_SAFE + "?")
    port = DEFAULT_PORTS[scheme]
    url = f"{scheme}://{host}{path}"
    return NormalizedURL(scheme, host, port, path, url)
