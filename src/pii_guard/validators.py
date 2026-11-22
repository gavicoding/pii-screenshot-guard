"""Deterministic format & checksum validators to minimize false positives."""

from __future__ import annotations

import re


def _digits_only(value: str) -> str:
    return re.sub(r"\D", "", value)


def is_valid_cpf(value: str) -> bool:
    """Validate Brazilian CPF using official mod-11 check digits."""
    digits = _digits_only(value)
    if len(digits) != 11 or len(set(digits)) == 1:
        return False

    first_sum = sum(int(d) * w for d, w in zip(digits[:9], range(10, 1, -1)))
    first_digit = (first_sum * 10) % 11 % 10
    if int(digits[9]) != first_digit:
        return False

    second_sum = sum(int(d) * w for d, w in zip(digits[:10], range(11, 1, -1)))
    second_digit = (second_sum * 10) % 11 % 10
    return int(digits[10]) == second_digit


def is_valid_cnpj(value: str) -> bool:
    """Validate Brazilian CNPJ using official mod-11 check digits."""
    digits = _digits_only(value)
    if len(digits) != 14 or len(set(digits)) == 1:
        return False

    weights_first = (5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)
    weights_second = (6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)

    s1 = sum(int(d) * w for d, w in zip(digits[:12], weights_first))
    r1 = s1 % 11
    d1 = 0 if r1 < 2 else 11 - r1
    if int(digits[12]) != d1:
        return False

    s2 = sum(int(d) * w for d, w in zip(digits[:13], weights_second))
    r2 = s2 % 11
    d2 = 0 if r2 < 2 else 11 - r2
    return int(digits[13]) == d2


def is_valid_luhn(value: str) -> bool:
    """Validate payment card numbers with the Luhn checksum."""
    digits = _digits_only(value)
    if not (13 <= len(digits) <= 19) or len(set(digits)) == 1:
        return False

    total = 0
    reverse_digits = digits[::-1]
    for idx, ch in enumerate(reverse_digits):
        num = int(ch)
        if idx % 2 == 1:
            num *= 2
            if num > 9:
                num -= 9
        total += num
    return total % 10 == 0


def is_rfc1918_ipv4(ip: str) -> bool:
    """Return True if ip is a valid private RFC 1918 IPv4 address."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if any(o < 0 or o > 255 for o in octets):
        return False

    a, b, _, _ = octets
    return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
