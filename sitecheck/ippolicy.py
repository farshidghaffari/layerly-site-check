"""Destination IP policy (architecture component [3]): only global unicast addresses pass."""
import ipaddress

BLOCKED_V4 = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "255.255.255.255/32",
)]
BLOCKED_V6 = [ipaddress.ip_network(n) for n in (
    "::/128", "::1/128", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32",
    "2002::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
)]
NAT64_WKP = ipaddress.ip_network("64:ff9b::/96")


def check_ip(value):
    """Return (allowed: bool, reason: str). Reason names the blocking rule."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False, "unparseable_address"
    if ip.version == 6:
        if ip.ipv4_mapped is not None:
            ok, why = check_ip(str(ip.ipv4_mapped))
            return ok, why if ok else f"ipv4_mapped:{why}"
        if ip in NAT64_WKP:
            embedded = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
            ok, why = check_ip(str(embedded))
            return ok, why if ok else f"nat64:{why}"
        for net in BLOCKED_V6:
            if ip in net:
                return False, f"blocked:{net}"
    else:
        for net in BLOCKED_V4:
            if ip in net:
                return False, f"blocked:{net}"
    if not ip.is_global:
        return False, "not_global"
    return True, "global"


def check_all(addresses):
    """Every resolved address must be public; one non-public address rejects the host."""
    if not addresses:
        return False, "no_addresses"
    for a in addresses:
        ok, why = check_ip(a)
        if not ok:
            return False, f"{a}:{why}"
    return True, "global"
