#!/usr/bin/env python3
"""
Build an AdGuard Home IPv6 (AAAA) blocklist from a master domain list.

This script:
  1. Normalises and validates source/domains.txt
  2. Sorts and de-duplicates it
  3. Rewrites source/domains.txt in canonical sorted form
  4. Generates generated/adguard-ipv6-blocklist.txt

Rule format:
  ||example.com^$dnstype=AAAA,dnsrewrite=NOERROR
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILE = REPO_ROOT / "source" / "domains.txt"
OUTPUT_FILE = REPO_ROOT / "generated" / "adguard-ipv6-blocklist.txt"


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)


def normalise_domain(line: str) -> str | None:
    cleaned = line.strip()

    if not cleaned or cleaned.startswith("#"):
        return None

    if "#" in cleaned:
        cleaned = cleaned.split("#", 1)[0].strip()

    cleaned = cleaned.lower()
    cleaned = cleaned.removeprefix("https://").removeprefix("http://")
    cleaned = cleaned.lstrip("*.")  # remove wildcard prefix
    cleaned = cleaned.rstrip(".")

    return cleaned or None


def validate_domain(domain: str) -> bool:
    if "xn--" in domain:  # allow punycode
        return True

    return DOMAIN_PATTERN.match(domain) is not None


def build_rules(domains: list[str]) -> list[str]:
    return [
        f"||{domain}^$dnstype=AAAA,dnsrewrite=NOERROR"
        for domain in domains
    ]


def rewrite_source_file(domains: list[str]) -> None:
    """
    Overwrite source/domains.txt in clean, sorted canonical form.
    """
    header = [
        "# Domain Guardrails - Master Domain List",
        "# One domain per line.",
        "# This file is auto-sorted and normalised by CI.",
        "",
    ]

    SOURCE_FILE.write_text(
        "\n".join(header + domains) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    if not SOURCE_FILE.exists():
        print(f"ERROR: Missing source file: {SOURCE_FILE}", file=sys.stderr)
        return 2

    raw_lines = SOURCE_FILE.read_text(encoding="utf-8").splitlines()

    cleaned_domains: list[str] = []
    warnings: list[str] = []

    for idx, line in enumerate(raw_lines, start=1):
        domain = normalise_domain(line)
        if domain is None:
            continue

        if not validate_domain(domain):
            warnings.append(f"Line {idx}: Invalid domain skipped: {domain!r}")
            continue

        cleaned_domains.append(domain)

    # De-duplicate and sort deterministically
    deduped_domains = sorted(set(cleaned_domains))

    # Rewrite canonical source file
    rewrite_source_file(deduped_domains)

    # Generate AdGuard rules in same order
    rules = build_rules(deduped_domains)

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    header = [
        "! Title: Domain Guardrails - IPv6 (AAAA) Blocklist",
        "! Description: Generated from source/domains.txt",
        f"! Generated: {generated_at}",
        "!",
        "! Format: ||domain^$dnstype=AAAA,dnsrewrite=NOERROR",
        "!",
    ]

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(
        "\n".join(header + rules) + "\n",
        encoding="utf-8",
    )

    print(f"Processed {len(deduped_domains)} domains.")
    if warnings:
        print("\nWarnings:")
        for w in warnings:
            print(" -", w)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
