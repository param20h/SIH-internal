"""Shared IP-address classification helpers."""

import ipaddress

# RFC 5737 (IPv4) / RFC 3849 (IPv6) documentation-only ranges. Python's
# ipaddress module lumps these into is_private alongside genuine RFC 1918
# space, but they represent a different forensic category: "reserved for
# writing examples," not "this host is on someone's private LAN." Only the
# latter is the signal bogon_ip_in_path cares about, so these are carved
# out explicitly rather than flagged.
_DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
]


def is_bogon(ip_text: str) -> bool:
    """True if `ip_text` is a private, loopback, link-local, reserved, or
    otherwise non-publicly-routable address -- one that should never appear
    as a hop's claimed sending address on a chain crossing the public
    internet. Documentation/example ranges (RFC 5737/3849) are excluded --
    see module docstring."""
    try:
        addr = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    if any(addr in network for network in _DOCUMENTATION_NETWORKS):
        return False
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_unspecified
        or addr.is_multicast
    )
