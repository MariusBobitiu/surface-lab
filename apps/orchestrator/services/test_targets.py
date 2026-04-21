import ipaddress
import socket
import unittest

from services.targets import (
    INVALID_TARGET_MESSAGE,
    UNSAFE_TARGET_MESSAGE,
    TargetValidationError,
    validate_scan_target,
)


class ValidateScanTargetTests(unittest.TestCase):
    def test_allows_https_hostname(self) -> None:
        target = validate_scan_target(
            "https://example.com",
            resolver=lambda hostname: {ipaddress.ip_address("93.184.216.34")},
        )

        self.assertEqual(target, "https://example.com")

    def test_normalizes_hostname_without_scheme(self) -> None:
        target = validate_scan_target(
            " example.com ",
            resolver=lambda hostname: {ipaddress.ip_address("93.184.216.34")},
        )

        self.assertEqual(target, "https://example.com")

    def test_allows_public_ip_target(self) -> None:
        target = validate_scan_target("https://8.8.8.8")

        self.assertEqual(target, "https://8.8.8.8")

    def test_rejects_empty_target(self) -> None:
        with self.assertRaisesRegex(TargetValidationError, INVALID_TARGET_MESSAGE):
            validate_scan_target("   ")

    def test_rejects_localhost_hostname(self) -> None:
        with self.assertRaisesRegex(TargetValidationError, UNSAFE_TARGET_MESSAGE):
            validate_scan_target("localhost")

    def test_rejects_ipv4_loopback(self) -> None:
        with self.assertRaisesRegex(TargetValidationError, UNSAFE_TARGET_MESSAGE):
            validate_scan_target("http://127.0.0.1")

    def test_rejects_private_ipv4(self) -> None:
        for target in ("10.0.0.1", "192.168.1.1", "172.16.0.10"):
            with self.subTest(target=target):
                with self.assertRaisesRegex(TargetValidationError, UNSAFE_TARGET_MESSAGE):
                    validate_scan_target(target)

    def test_rejects_link_local_metadata_ip(self) -> None:
        with self.assertRaisesRegex(TargetValidationError, UNSAFE_TARGET_MESSAGE):
            validate_scan_target("http://169.254.169.254")

    def test_rejects_ipv6_local_targets(self) -> None:
        for target in ("http://[::1]", "http://[fe80::1]", "http://[fc00::1]"):
            with self.subTest(target=target):
                with self.assertRaisesRegex(TargetValidationError, UNSAFE_TARGET_MESSAGE):
                    validate_scan_target(target)

    def test_rejects_hostname_resolving_to_private_ip(self) -> None:
        with self.assertRaisesRegex(TargetValidationError, UNSAFE_TARGET_MESSAGE):
            validate_scan_target(
                "internal.example.test",
                resolver=lambda hostname: {ipaddress.ip_address("10.0.0.7")},
            )

    def test_rejects_hostname_when_dns_resolution_fails(self) -> None:
        def failing_resolver(hostname: str) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
            raise TargetValidationError(INVALID_TARGET_MESSAGE) from socket.gaierror("dns failed")

        with self.assertRaisesRegex(TargetValidationError, INVALID_TARGET_MESSAGE):
            validate_scan_target("missing.example.test", resolver=failing_resolver)
