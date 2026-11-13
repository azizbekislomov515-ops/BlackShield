"""Domain normalization and the never-block list.

Feeds list URLs, hosts-file lines or bare names. Everything becomes a lower-case ASCII (IDNA)
name without a trailing dot, or is rejected with a reason. Web Shield blocks by DNS, i.e. a whole
host and everything under it, so phishing on a shared platform (a Google Doc, a GitHub Pages
site's parent, a URL shortener) must never block the platform itself: see ``protected_reason``.
"""

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlsplit

from app.db.models import DOMAIN_CATEGORIES

MAX_DOMAIN_LENGTH = 253
# LDH labels; underscores appear in real malware hostnames (and resolvers accept them).
_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")

#: Never blocked, nor anything under them: first-party services where one bad URL is never a
#: reason to break the whole service (and DNS cannot block a single URL).
NEVER_BLOCK_TREES = frozenset(
    {
        "android.com",
        "apple.com",
        "amazon.com",
        "bing.com",
        "cloudflare.com",
        "discord.com",
        "dropbox.com",
        "facebook.com",
        "github.com",
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "icloud.com",
        "instagram.com",
        "linkedin.com",
        "live.com",
        "microsoft.com",
        "microsoftonline.com",
        "office.com",
        "outlook.com",
        "paypal.com",
        "telegram.org",
        "t.me",
        "whatsapp.com",
        "whatsapp.net",
        "wikipedia.org",
        "windows.net",
        "x.com",
        "twitter.com",
        "yahoo.com",
        "youtube.com",
        # URL shorteners and link hubs: blocking them breaks every legitimate link.
        "bit.ly",
        "forms.gle",
        "goo.gl",
        "linktr.ee",
        "t.co",
        "tinyurl.com",
    }
)

#: Shared hosting roots: customers' subdomains may be blocked, the root itself never.
NEVER_BLOCK_EXACT = frozenset(
    {
        "000webhostapp.com",
        "amazonaws.com",
        "appspot.com",
        "azurewebsites.net",
        "blogspot.com",
        "cloudfront.net",
        "duckdns.org",
        "firebaseapp.com",
        "github.io",
        "gitlab.io",
        "googleusercontent.com",
        "herokuapp.com",
        "netlify.app",
        "ngrok-free.app",
        "ngrok.io",
        "pages.dev",
        "r2.dev",
        "vercel.app",
        "web.app",
        "weebly.com",
        "wixsite.com",
        "wordpress.com",
        "workers.dev",
    }
)


class InvalidDomain(ValueError):
    """Not a blockable domain. The message says why."""


class ProtectedDomain(InvalidDomain):
    """A valid domain on the never-block list."""


@dataclass(frozen=True)
class DomainRecord:
    domain: str
    category: str
    source: str
    first_seen: datetime


@dataclass(frozen=True)
class DomainRemoval:
    domain: str


def normalize_domain(raw: str) -> str:
    """A URL, ``host[:port]`` or name → canonical domain. Raises InvalidDomain."""
    value = raw.strip()
    if not value:
        raise InvalidDomain("empty")
    if "://" in value or "/" in value or "?" in value:
        try:
            host = urlsplit(value if "://" in value else f"http://{value}").hostname
        except ValueError as exc:
            raise InvalidDomain(f"not a URL ({exc})") from exc
        value = host or ""
    elif value.count(":") == 1:
        value = value.split(":", 1)[0]  # host:port
    value = value.strip().lower().rstrip(".")
    value = value.removeprefix("*.")
    if not value:
        raise InvalidDomain("no host")
    try:
        ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        pass
    else:
        raise InvalidDomain("an IP address, not a domain")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidDomain(f"not a valid internationalized name ({exc})") from exc
    labels = value.split(".")
    if len(value) > MAX_DOMAIN_LENGTH or len(labels) < 2:
        raise InvalidDomain("needs at least two labels and at most 253 characters")
    if not all(_LABEL.match(label) for label in labels):
        raise InvalidDomain("contains an invalid label")
    if labels[-1].isdigit():
        raise InvalidDomain("numeric top-level label")
    return value


def protected_reason(domain: str) -> str | None:
    """Why ``domain`` must never be blocked, or None."""
    if domain in NEVER_BLOCK_EXACT:
        return f"{domain} is a shared hosting root"
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        parent = ".".join(labels[i:])
        if parent in NEVER_BLOCK_TREES:
            return f"{domain} belongs to {parent}, which is never blocked"
    return None


def blockable(raw: str) -> str:
    """normalize_domain() plus the never-block list. Raises InvalidDomain."""
    domain = normalize_domain(raw)
    reason = protected_reason(domain)
    if reason:
        raise ProtectedDomain(reason)
    return domain


def validate_category(category: str) -> str:
    value = category.strip().lower()
    if value not in DOMAIN_CATEGORIES:
        raise InvalidDomain(f"unknown category {category!r}")
    return value
