#!/usr/bin/env python3
"""
Build an AdGuard Home IPv6 (AAAA) suppression list from one or many source files.

This script:
  1) Reads domains from *either*:
      - sources/**/*.txt  (preferred; unlimited files, recursive)
      - source/domains.txt (fallback for backwards compatibility)
  2) Normalises + validates
  3) Sorts + de-duplicates
  4) Rewrites source/domains.txt in canonical sorted form (single master list)
  5) Generates generated/adguard-ipv6-blocklist.txt

Rule format:
  ||example.com^$dnstype=AAAA,dnsrewrite=NOERROR
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
import sys
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]

# Preferred: unlimited source files
SOURCES_DIR = REPO_ROOT / "sources"

# Backwards compatible fallback (your current layout)
SOURCE_FILE_FALLBACK = REPO_ROOT / "source" / "domains.txt"

# Canonical master list we maintain for review/diff
CANONICAL_MASTER_FILE = REPO_ROOT / "source" / "domains.txt"

# Output AdGuard list
OUTPUT_FILE = REPO_ROOT / "generated" / "adguard-ipv6-blocklist.txt"


DOMAIN_PATTERN = re.compile(
    # Very standard-ish hostname validation (kept intentionally permissive)
    r"^(?=.{1,253}$)"
    r"(?!-)"
    r"(?:[a-z0-9-]{1,63}\.)+"
    r"[a-z]{2,63}$",
    re.IGNORECASE,
)


def normalise_domain(line: str) -> str | None:
    cleaned = line.strip()
    if not cleaned or cleaned.startswith("#"):
        return None

    # Strip inline comments
    if "#" in cleaned:
        cleaned = cleaned.split("#", 1)[0].strip()

    cleaned = cleaned.lower()

    # Strip scheme if someone pasted a URL
    cleaned = cleaned.removeprefix("https://").removeprefix("http://")

    # Remove wildcard prefix
    cleaned = cleaned.lstrip("*.")
    cleaned = cleaned.lstrip("*.")  # (safe redundancy)

    # Remove trailing dot
    cleaned = cleaned.rstrip(".")

    # If someone pasted a path, keep only the host portion
    if "/" in cleaned:
        cleaned = cleaned.split("/", 1)[0].strip()

    return cleaned or None


def validate_domain(domain: str) -> bool:
    # Allow punycode (common in IDN domains)
    if "xn--" in domain:
        return True
    return DOMAIN_PATTERN.match(domain) is not None


def build_rules(domains: list[str]) -> list[str]:
    return [f"||{domain}^$dnstype=AAAA,dnsrewrite=NOERROR" for domain in domains]


def rewrite_master_file(domains: list[str]) -> None:
    """
    Overwrite source/domains.txt in clean, sorted canonical form.
    """
    header = [
        "# Domain Guardrails - Master Domain List",
        "# One domain per line.",
        "# This file is auto-sorted and normalised by CI.",
        "#",
        "# Preferred source of truth is sources/**/*.txt (this file is generated from them).",
        "",
    ]
    CANONICAL_MASTER_FILE.parent.mkdir(parents=True, exist_ok=True)
    CANONICAL_MASTER_FILE.write_text(
        "\n".join(header + domains) + "\n",
        encoding="utf-8",
    )


def iter_source_files() -> list[Path]:
    """
    Prefer sources/**/*.txt. If none exist, fall back to source/domains.txt.
    """
    if SOURCES_DIR.exists() and SOURCES_DIR.is_dir():
        files = sorted([p for p in SOURCES_DIR.rglob("*.txt") if p.is_file()])
        if files:
            return files

    # Fallback to the existing single file
    if SOURCE_FILE_FALLBACK.exists():
        return [SOURCE_FILE_FALLBACK]

    return []


def read_lines_from_files(files: Iterable[Path]) -> list[tuple[Path, list[str]]]:
    """
    Returns list of (file_path, lines)
    """
    out: list[tuple[Path, list[str]]] = []
    for file_path in files:
        text = file_path.read_text(encoding="utf-8", errors="replace")
        out.append((file_path, text.splitlines()))
    return out


def main() -> int:
    source_files = iter_source_files()
    if not source_files:
        print(
            "ERROR: No input files found.\n"
            f"Expected either:\n"
            f"  - {SOURCES_DIR}/**/*.txt (preferred)\n"
            f"  - {SOURCE_FILE_FALLBACK} (fallback)\n",
            file=sys.stderr,
        )
        return 2

    # Read everything
    file_lines = read_lines_from_files(source_files)

    cleaned_domains: list[str] = []
    warnings: list[str] = []

    for file_path, lines in file_lines:
        for idx, line in enumerate(lines, start=1):
            domain = normalise_domain(line)
            if domain is None:
                continue

            if not validate_domain(domain):
                warnings.append(f"{file_path.relative_to(REPO_ROOT)}:{idx}: Invalid domain skipped: {domain!r}")
                continue

            cleaned_domains.append(domain)

    # De-duplicate and sort deterministically
    deduped_domains = sorted(set(cleaned_domains))

    # Rewrite canonical master file (single place to review)
    rewrite_master_file(deduped_domains)

    # Generate AdGuard rules
    rules = build_rules(deduped_domains)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Header includes provenance
    provenance = [f"!   - {p.relative_to(REPO_ROOT)}" for p in source_files]

    header = [
        "! Title: Domain Guardrails - IPv6 (AAAA) Blocklist",
        "! Description: Generated from sources/**/*.txt (or fallback source/domains.txt)",
        f"! Generated: {generated_at}",
        "!",
        "! Inputs:",
        *provenance,
        "!",
        "! Format: ||domain^$dnstype=AAAA,dnsrewrite=NOERROR",
        "!",
    ]

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(
        "\n".join(header + rules) + "\n",
        encoding="utf-8",
    )

    print(f"Input files: {len(source_files)}")
    print(f"Processed {len(deduped_domains)} unique domains.")
    print(f"Master list written: {CANONICAL_MASTER_FILE.relative_to(REPO_ROOT)}")
    print(f"AdGuard list written: {OUTPUT_FILE.relative_to(REPO_ROOT)}")

    if warnings:
        print("\nWarnings:")
        for w in warnings:
            print(" -", w)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
