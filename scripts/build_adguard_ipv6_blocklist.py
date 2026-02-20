#!/usr/bin/env python3
"""
Build an AdGuard Home filter list that blocks IPv6 (AAAA) DNS answers
for a curated set of domains.

Input:
  - source/domains.txt  (one domain per line, optional comments with #)

Output:
  - generated/adguard-ipv6-blocklist.txt

Rule format:
  ||example.com^$dnstype=AAAA,dnsrewrite=NOERROR

Meaning:
  - Match the domain and its subdomains (||example.com^)
  - Only apply to AAAA queries (IPv6) ($dnstype=AAAA)
  - Respond with an empty NOERROR (dnsrewrite=NOERROR)

Notes:
  - $dnstype is supported by AdGuard DNS filtering syntax used in AdGuard Home.  [oai_citation:1‡AdGuard DNS — ad-blocking DNS server](https://adguard-dns.com/kb/general/dns-filtering-syntax/?utm_source=chatgpt.com)
  - Returning empty NOERROR for rewrites is referenced in AdGuard Home discussions/changes.  [oai_citation:2‡GitHub](https://github.com/AdguardTeam/AdGuardHome/discussions/4021?utm_source=chatgpt.com)
"""

from __future__ import annotations

from dataclasses import dataclass
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


@dataclass(frozen=True)
class BuildResult:
    domains_in: int
    domains_out: int
    warnings: list[str]


def normalise_domain(line: str) -> str | None:
    """
    Convert an input line into a clean domain name or None if it should be skipped.
    """
    # Strip whitespace
    cleaned = line.strip()

    # Ignore blank lines
    if not cleaned:
        return None

    # Ignore full-line comments
    if cleaned.startswith("#"):
        return None

    # Remove inline comments: "example.com  # comment"
    if "#" in cleaned:
        cleaned = cleaned.split("#", 1)[0].strip()

    # Lowercase domains; DNS is case-insensitive
    cleaned = cleaned.lower()

    # If someone pasted a scheme or wildcard, we try to gently correct.
    cleaned = cleaned.removeprefix("https://").removeprefix("http://")
    cleaned = cleaned.lstrip("*.")  # "*.example.com" -> "example.com"

    # Remove trailing dot
    cleaned = cleaned.rstrip(".")

    return cleaned or None


def validate_domain(domain: str) -> bool:
    """
    Conservative domain validator (keeps obvious junk out of your output).
    You can relax this if you deliberately want exotic TLDs/punycode patterns.
    """
    # Allow punycode labels (xn--)
    if "xn--" in domain:
        return True

    return DOMAIN_PATTERN.match(domain) is not None


def build_rules(domains: list[str]) -> list[str]:
    """
    Build AdGuard filter rules that block AAAA queries for each domain.
    """
    rules: list[str] = []
    for domain in domains:
        # ||example.com^ matches example.com and subdomains in AdGuard rule syntax
        # $dnstype=AAAA targets IPv6 queries; dnsrewrite=NOERROR returns empty success.
        rules.append(f"||{domain}^$dnstype=AAAA,dnsrewrite=NOERROR")
    return rules


def main() -> int:
    if not SOURCE_FILE.exists():
        print(f"ERROR: Missing source file: {SOURCE_FILE}", file=sys.stderr)
        return 2

    raw_lines = SOURCE_FILE.read_text(encoding="utf-8").splitlines()

    warnings: list[str] = []
    cleaned_domains: list[str] = []

    for idx, line in enumerate(raw_lines, start=1):
        domain = normalise_domain(line)
        if domain is None:
            continue

        if not validate_domain(domain):
            warnings.append(f"Line {idx}: Skipping invalid-looking domain: {domain!r}")
            continue

        cleaned_domains.append(domain)

    # De-duplicate while preserving sort order (stable)
    deduped_domains = list(dict.fromkeys(cleaned_domains))

    # Sort for deterministic output (makes diffs clean)
    deduped_domains.sort()

    rules = build_rules(deduped_domains)

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    header = [
        "! Title: Domain Guardrails - IPv6 (AAAA) Blocklist",
        "! Description: Generated from source/domains.txt. Blocks IPv6 AAAA answers only.",
        "! Syntax: AdGuard DNS filtering rules",
        f"! Generated: {generated_at}",
        "!",
        "! Rule format: ||example.com^$dnstype=AAAA,dnsrewrite=NOERROR",
        "!",
    ]

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text("\n".join(header + rules) + "\n", encoding="utf-8")

    result = BuildResult(
        domains_in=len(cleaned_domains),
        domains_out=len(deduped_domains),
        warnings=warnings,
    )

    print(f"Wrote {OUTPUT_FILE} with {result.domains_out} domains (from {result.domains_in} input lines).")
    if result.warnings:
        print("\nWarnings:")
        for w in result.warnings:
            print(f" - {w}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
