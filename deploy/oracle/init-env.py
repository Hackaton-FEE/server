"""Create local deployment secrets without printing or overwriting them (Python 3.10+)."""

import argparse
import ipaddress
import json
import os
import re
import secrets
from pathlib import Path
from urllib.parse import urlsplit


def hostname(value: str) -> str:
    value = value.lower()
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise argparse.ArgumentTypeError("Use a public DNS hostname, not an IP address")
    labels = value.split(".")
    if (
        len(value) > 253
        or len(labels) < 2
        or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in labels)
    ):
        raise argparse.ArgumentTypeError("Use a DNS hostname without https://, port or path")
    return value


def https_origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        _ = parsed.port
        valid = (
            parsed.scheme == "https"
            and parsed.hostname
            and not parsed.username
            and not parsed.password
            and not parsed.path
            and not parsed.query
            and not parsed.fragment
            and not any(c in value for c in "*'$\r\n\t ")
        )
    except ValueError:
        valid = False
    if not valid:
        raise argparse.ArgumentTypeError("Use an exact HTTPS origin without a trailing slash")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("domain", type=hostname, help="API hostname, e.g. api.example.com")
    parser.add_argument("--web-origin", type=https_origin, action="append", default=[])
    parser.add_argument("--output", type=Path, default=Path(".env.production"))
    args = parser.parse_args()
    content = (
        f"FEE_API_DOMAIN={args.domain}\n"
        f"POSTGRES_PASSWORD={secrets.token_hex(32)}\n"
        f"FEE_AUTH_SECRET_KEY={secrets.token_urlsafe(48)}\n"
        f"FEE_CORS_ORIGINS='{json.dumps(args.web_origin)}'\n"
    )
    try:
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        parser.exit(1, f"{args.output} already exists; existing secrets were preserved.\n")
    with os.fdopen(descriptor, "w") as destination:
        destination.write(content)
    print(f"Created {args.output} with mode 0600. Keep it private and back it up securely.")


if __name__ == "__main__":
    main()
