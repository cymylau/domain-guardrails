#!/usr/bin/env python3
"""
Build a combined AdGuard Home IPv6 (AAAA) suppression list from one or more source files.

Requirements (as requested):
- Source folder is "/source" (repo-relative: ./source)
- Destination is "generated/adguard-ipv6-blocklist.txt"
- /source contains one or more .txt files
- Combine all files, de-duplicate, sort alphabetically
- Output rules are in AdGuard DNS filtering syntax:
    ||example.com^$dnstype=AAAA,dnsrewrite=NOERROR

Input formats supported in source/*.txt:
- One domain per line:
    example.com
    sub.example.com
- AdGuard-style rule lines:
    ||example.com^$dnstype=AAAA
    ||example.com^$dnstype=AAAA,dnsrewrite=NOERROR
- Comments:
    # comment
    example.com   # inline comment

Notes:
- This script deduplicates by domain (not by full rule line) to keep output stable.
- Wildcards like "*.example.com" are normalized to "example.com" (AdGuard ||example.com^ matches subdomains anyway).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
import sys
from typing import Iterable, List, Set, Tuple


REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = REPO_ROOT / "source"
OUTPUT_FILE = REPO_ROOT / "generated" / "adguard-ipv6-blocklist.txt"


# Matches AdGuard rule lines like:
#   ||example.com^$dnstype=AAAA
# and extracts "example.com"
ADGUARD_RULE_DOMAIN_REGEX = re.compile(
    r"""^\s*\|\|(?P<domain>[A-Za-z0-9.-]+\.[A-Za-z]{2,})\^\s*(?:\$.*)?\s*$"""
)

# Basic domain validation (permissive enough for typical use; allows punycode via xn--)
DOMAIN_VALIDATION_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)


def iter_source_files(source_dir: Path) -> List[Path]:
    """
    Return all .txt files under source_dir (recursive), sorted.
    """
    if not source_dir.exists():
        raise FileNotFoundError(f"Source directory not found: {source_dir}")
    if not source_dir.is_dir():
        raise NotADirectoryError(f"Source path is not a directory: {source_dir}")

    files = sorted([p for p in source_dir.rglob("*.txt") if p.is_file()])
    if not files:
        raise RuntimeError(f"No .txt files found under: {source_dir}")
    return files


def normalize_domain(domain: str) -> str:
    """
    Normalize a domain:
    - lowercase
    - strip scheme
    - remove leading wildcard '*.'
    - strip trailing dot
    - strip any path portion
    """
    d = domain.strip().lower()

    # Strip schemes if someone pasted a URL
    if d.startswith("https://"):
        d = d[len("https://") :]
    elif d.startswith("http://"):
        d = d[len("http://") :]

    # Remove wildcard prefix
    if d.startswith("*."):
        d = d[2:]

    # If there's a path, keep only host portion
    if "/" in d:
        d = d.split("/", 1)[0].strip()

    # Strip trailing dot
    d = d.rstrip(".")

    return d


def is_valid_domain(domain: str) -> bool:
    # Allow punycode domains
    if "xn--" in domain:
        return True
    return DOMAIN_VALIDATION_REGEX.match(domain) is not None


def extract_domain_from_line(line: str) -> str | None:
    """
    Extract a domain from either:
    - plain domain line (example.com)
    - AdGuard rule line (||example.com^$...)
    Returns normalized domain or None if the line should be ignored.
    """
    stripped = line.strip()
    if not stripped:
        return None
    if stripped.startswith("#"):
        return None

    # Remove inline comments
    if "#" in stripped:
        stripped = stripped.split("#", 1)[0].strip()
        if not stripped:
            return None

    # AdGuard rule line?
    match = ADGUARD_RULE_DOMAIN_REGEX.match(stripped)
    if match:
        return normalize_domain(match.group("domain"))

    # Otherwise treat as plain domain
    return normalize_domain(stripped)


def build_adguard_rule(domain: str) -> str:
    return f"||{domain}^$dnstype=AAAA,dnsrewrite=NOERROR"


def read_domains_from_files(files: Iterable[Path]) -> Tuple[Set[str], List[str]]:
    """
    Returns:
      - set of unique domains
      - list of warning strings
    """
    domains: Set[str] = set()
    warnings: List[str] = []

    for file_path in files:
        text = file_path.read_text(encoding="utf-8", errors="replace")
        for line_number, raw_line in enumerate(text.splitlines(), start=1):
            domain = extract_domain_from_line(raw_line)
            if domain is None:
                continue

            if not is_valid_domain(domain):
                warnings.append(
                    f"{file_path.relative_to(REPO_ROOT)}:{line_number}: skipped invalid domain: {domain!r}"
                )
                continue

            domains.add(domain)

    return domains, warnings


def write_output(
    output_file: Path,
    rules: List[str],
    source_files: List[Path],
) -> None:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    provenance_lines = [f"!   - {p.relative_to(REPO_ROOT).as_posix()}" for p in source_files]

    header = [
        "! Title: Domain Guardrails - IPv6 (AAAA) Suppression List",
        "! Description: Generated from ./source/*.txt (combined, deduped, sorted)",
        f"! Generated: {generated_at}",
        "!",
        "! Inputs:",
        *provenance_lines,
        "!",
        "! Format: ||domain^$dnstype=AAAA,dnsrewrite=NOERROR",
        "!",
    ]

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text("\n".join(header + rules) + "\n", encoding="utf-8")


def main() -> int:
    try:
        source_files = iter_source_files(SOURCE_DIR)
        domains, warnings = read_domains_from_files(source_files)

        domains_sorted = sorted(domains)
        rules_sorted = [build_adguard_rule(d) for d in domains_sorted]

        write_output(OUTPUT_FILE, rules_sorted, source_files)

        print(f"Source dir        : {SOURCE_DIR.relative_to(REPO_ROOT)}")
        print(f"Source files      : {len(source_files)}")
        print(f"Unique domains    : {len(domains_sorted)}")
        print(f"Output            : {OUTPUT_FILE.relative_to(REPO_ROOT)}")

        if warnings:
            print("\nWarnings:")
            for w in warnings:
                print(f" - {w}")

        return 0

    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
