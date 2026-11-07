#!/usr/bin/env python3
"""Compile operator-reviewed domains to dnsmasq rules; no downloads or browsing collection."""
import argparse
import hashlib
import ipaddress
from pathlib import Path
import re


def domain(value):
    value = value.strip().rstrip(".").lower().encode("idna").decode("ascii")
    if not 1 < len(value) <= 253 or "." not in value:
        raise ValueError("Expected a domain with at least two labels")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in value.split(".")):
        raise ValueError("Invalid domain")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError("IP literals are not domain block rules")


def read_domains(path):
    if path.stat().st_size > 16*1024*1024:
        raise ValueError("Blocklist is too large for this prototype")
    result = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        result.add(domain(line))
    return result


def compile_rules(blocked, allowed):
    # Avoid ambiguous same-name allow/block rules; more-specific allow rules override parents.
    lines = ["# Generated domain policy. No query logging is enabled here."]
    lines += ["local=/"+name+"/" for name in sorted(blocked-allowed)]
    lines += ["server=/"+name+"/#" for name in sorted(allowed)]
    return "\n".join(lines)+"\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("blocked", type=Path, help="Reviewed plain domain-per-line list; no URLs, wildcard or hosts format")
    parser.add_argument("output", type=Path)
    parser.add_argument("--allow", type=Path)
    args = parser.parse_args()
    blocked = read_domains(args.blocked)
    allowed = read_domains(args.allow) if args.allow else set()
    text = compile_rules(blocked, allowed)
    with args.output.open("x", encoding="utf-8") as out:
        out.write(text)
    print(f"Wrote {len(blocked-allowed)} blocking rules and {len(allowed)} exceptions.")
    print("Rules SHA256:", hashlib.sha256(text.encode()).hexdigest())
    print("Review, test with dnsmasq --test, then install into your filtered resolver. No service has been changed.")


if __name__ == "__main__":
    main()
