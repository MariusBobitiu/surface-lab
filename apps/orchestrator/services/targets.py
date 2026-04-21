import ipaddress
import socket
from collections.abc import Callable
from urllib.parse import SplitResult, urlsplit, urlunsplit


class TargetValidationError(ValueError):
    pass


Resolver = Callable[[str], set[ipaddress.IPv4Address | ipaddress.IPv6Address]]

INVALID_TARGET_MESSAGE = "Invalid scan target"
UNSAFE_TARGET_MESSAGE = "Private or local addresses cannot be scanned"
ALLOWED_SCHEMES = {"http", "https"}
LOCAL_HOSTNAMES = {"localhost", "localhost.localdomain"}


def validate_scan_target(target: str, resolver: Resolver | None = None) -> str:
    normalized = normalize_target(target)
    hostname = normalized.hostname
    if hostname is None:
        raise TargetValidationError(INVALID_TARGET_MESSAGE)

    canonical_host = normalize_hostname(hostname)
    ip_address = parse_ip_address(canonical_host)
    if ip_address is not None:
        validate_public_ip(ip_address)
        return rebuild_target(normalized, canonical_host)

    resolved_ips = (resolver or resolve_hostname_ips)(canonical_host)
    if not resolved_ips:
        raise TargetValidationError(INVALID_TARGET_MESSAGE)

    for resolved_ip in resolved_ips:
        validate_public_ip(resolved_ip)

    return rebuild_target(normalized, canonical_host)


def normalize_target(target: str) -> SplitResult:
    trimmed = target.strip()
    if not trimmed:
        raise TargetValidationError(INVALID_TARGET_MESSAGE)

    candidate = trimmed if "://" in trimmed else f"https://{trimmed}"
    parsed = urlsplit(candidate)

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise TargetValidationError(INVALID_TARGET_MESSAGE)

    if not parsed.hostname:
        raise TargetValidationError(INVALID_TARGET_MESSAGE)

    if parsed.username or parsed.password:
        raise TargetValidationError(INVALID_TARGET_MESSAGE)

    try:
        parsed.port
    except ValueError as exc:
        raise TargetValidationError(INVALID_TARGET_MESSAGE) from exc

    return parsed


def normalize_hostname(hostname: str) -> str:
    normalized = hostname.rstrip(".").strip().lower()
    if not normalized:
        raise TargetValidationError(INVALID_TARGET_MESSAGE)

    if normalized in LOCAL_HOSTNAMES or normalized.endswith(".localhost"):
        raise TargetValidationError(UNSAFE_TARGET_MESSAGE)

    try:
        return normalized.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TargetValidationError(INVALID_TARGET_MESSAGE) from exc


def resolve_hostname_ips(hostname: str) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        address_info = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetValidationError(INVALID_TARGET_MESSAGE) from exc

    resolved_ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for entry in address_info:
        sockaddr = entry[4]
        if not sockaddr:
            continue

        resolved_ips.add(ipaddress.ip_address(sockaddr[0]))

    return resolved_ips


def parse_ip_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def validate_public_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    if address.is_global:
        return

    raise TargetValidationError(UNSAFE_TARGET_MESSAGE)


def rebuild_target(parsed: SplitResult, hostname: str) -> str:
    port = parsed.port
    host = hostname

    if ":" in host:
        host = f"[{host}]"

    netloc = host if port is None else f"{host}:{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path, parsed.query, ""))
