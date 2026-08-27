"""
================================================================================
user_discovery.py — Exposed User/Identity Discovery Module
================================================================================
Passive recon module: looks for USERNAMES / AUTHOR HANDLES / EMAILS /
SOCIAL LINKS that a website exposes ABOUT ITSELF on its own public pages
(WordPress author accounts, on-page contact emails, linked social profiles,
meta/JSON-LD author tags).

Scope & design notes:
  - This module lists identifiers the TARGET SITE has made public about
    itself. It does NOT profile any person, and it does NOT call osint.py
    or any other lookup service — that stays a separate, manual step for
    the operator, one identifier at a time, only for in-scope targets.
  - Everything here is passive / read-only (GET requests only). The
    WordPress "?author=N" check only probes a handful of low IDs — this is
    documented, well-known recon behavior, not brute forcing or auth
    bypass.
  - Same pattern as robots_analyzer.py: this module makes its own small
    set of requests rather than reusing http_scanner's capture, since
    author-enumeration endpoints are outside the normal header/cookie scan.

Standalone usage:
    python3 user_discovery.py
================================================================================
"""

import re
import requests
from urllib.parse import urlparse, urljoin

DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (SecurityScanner/1.0)"}

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

# Placeholder emails commonly used in HTML form "placeholder" attributes or
# example text (e.g. <input placeholder="you@domain.com">). These are not
# real addresses exposed by the site and would otherwise look identical to
# a genuine on-page email to the regex above.
PLACEHOLDER_EMAIL_LOCAL_PARTS = {
    "you", "your", "user", "username", "name", "email", "someone", "example",
    "test", "demo", "info", "hello", "yourname", "firstname.lastname", "john.doe",
    "jane.doe",
}
PLACEHOLDER_EMAIL_DOMAINS = {
    "domain.com", "example.com", "example.org", "yoursite.com", "yourdomain.com",
    "email.com", "test.com", "site.com", "company.com",
}

SOCIAL_PATTERNS = {
    "GitHub":    re.compile(r"github\.com/([A-Za-z0-9\-]+)"),
    "X/Twitter": re.compile(r"(?:twitter|x)\.com/([A-Za-z0-9_]+)"),
    "LinkedIn":  re.compile(r"linkedin\.com/in/([A-Za-z0-9\-]+)"),
    "Instagram": re.compile(r"instagram\.com/([A-Za-z0-9_.]+)"),
    "Facebook":  re.compile(r"facebook\.com/([A-Za-z0-9.\-]+)"),
    "Telegram":  re.compile(r"t\.me/([A-Za-z0-9_]+)"),
}

# Registrable domain(s) each pattern above is actually matching against.
# Used to SKIP a platform's own pattern when the scanned TARGET is that
# platform itself — e.g. scanning facebook.com will obviously contain
# hundreds of facebook.com/<word> links to its own nav/legal/marketing
# pages, none of which are "a user the site exposes". Those self-links
# are structurally indistinguishable from a real profile link by regex
# alone, so the only reliable fix is not extracting that platform's own
# handles when the target IS that platform.
SOCIAL_PLATFORM_DOMAINS = {
    "GitHub": "github.com",
    "X/Twitter": ("twitter.com", "x.com"),
    "LinkedIn": "linkedin.com",
    "Instagram": "instagram.com",
    "Facebook": "facebook.com",
    "Telegram": "t.me",
}

# Path segments that are clearly files/assets, not handles (e.g. Facebook's
# own "l.php" link-shim), regardless of platform.
_FILE_EXT_RE = re.compile(
    r"\.(php|html?|aspx?|jsp|js|css|png|jpe?g|gif|svg|webp|json|xml)$", re.I
)

# Extra, same-domain pages worth checking beyond the homepage — a LOT of
# sites put author/team/contact info here instead of (or in addition to)
# the homepage. Kept short and fixed on purpose: this stays passive recon
# (a handful of plain GET requests to well-known, public page paths), not a
# crawler or a brute-force directory scan.
COMMON_PAGES = [
    "/about", "/about-us", "/team", "/our-team", "/meet-the-team",
    "/contact", "/contact-us", "/staff", "/people", "/authors",
    "/author", "/blog", "/blog/author", "/company", "/leadership",
]

# Common non-username path segments the regexes above can accidentally pick
# up (share buttons, generic links, a site's OWN nav/footer pages) — filtered
# out so results stay clean. GitHub in particular has dozens of reserved
# top-level paths (features, pricing, security, team, ...) that match the
# same "github.com/<word>" shape as a real profile URL.
GENERIC_SOCIAL_JUNK = {
    "share", "sharer", "intent", "home", "login", "logout", "watch", "photo.php", "groups",
    # GitHub reserved / non-user paths
    "about", "about-us", "account", "api", "apps", "archive", "articles", "assets",
    "authors", "author", "blog", "business", "careers", "cmc",
    "changelog", "collections", "community", "company", "contact", "contact-us",
    "customer-stories", "customers", "docs",
    "discussions", "education", "enterprise", "events", "explore", "features",
    "get-started", "gist", "github", "help", "hovercards", "identicons", "integrations",
    "issues", "join", "join-waitlist", "leadership", "logos",
    "marketplace", "mcp", "mobile", "new", "newsletter", "notifications", "open-source", "org",
    "organizations", "orgs", "our-team", "partners", "people", "plans", "pricing", "privacy",
    "pulls", "raw", "readme", "releases",
    "resources", "search", "security", "services", "settings", "shop", "site", "site-policy",
    "sitemap", "social-impact", "sponsors", "sponsors-explore", "stars", "starred", "status",
    "styleguide", "support", "team", "terms", "timeline", "topics", "training",
    "trending", "trust-center", "undefined", "watching", "solutions", "customer",
    "premium-support", "fluidicon", "images", "why-github",
    # Facebook / Instagram / X marketing & policy pages (share the same
    # "site.com/<word>" shape as a real profile URL)
    "policies", "policy", "tos", "legal", "jobs", "press", "ads", "developers",
    "accounts", "signup", "reel", "reels", "stories", "i18n", "hashtag",
    # Newly observed on facebook.com's own nav/footer/link-shims
    "ad", "lite", "reg", "pages", "elementpath", "ourteam", "meettheteam",
    "contactus", "aboutus", "recover", "checkpoint", "login.php", "help.php",
    "media", "video", "videos", "photos", "notes", "gaming", "marketplace-",
    "safety", "transparency", "brandpermissions", "supportinbox",
}

# Normalized (letters/digits only, lowercase) form of the junk set above.
# Lets one entry like "our-team" also catch "ourteam", "Our_Team", etc.
# without having to list every punctuation variant by hand.
_JUNK_NORMALIZED = {re.sub(r"[^a-z0-9]", "", w.lower()) for w in GENERIC_SOCIAL_JUNK}

# Real usernames on these platforms are essentially never this short
# (Facebook/Instagram enforce 5+, X/Twitter 4+); short matches are almost
# always UI fragments ("ad", "id", "en"). Applied only to the generic
# social-handle extractor, not to WordPress usernames or emails.
MIN_HANDLE_LENGTH = 4


def normalize_url(url: str) -> str:
    """Same convention as the rest of the toolkit: default to https:// if
    no scheme was given."""
    url = url.strip()
    if not urlparse(url).scheme:
        url = "https://" + url
    return url


def _get(url: str, timeout: int):
    try:
        return requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        return None


def _extract_emails(html: str) -> list:
    found = sorted(set(EMAIL_RE.findall(html or "")))
    cleaned = []
    for e in found:
        # Drop obvious false positives like "logo@2x.png" picked up by the regex.
        if re.search(r"\.(png|jpe?g|gif|svg|webp)$", e, re.I):
            continue
        local, _, domain = e.partition("@")
        if local.lower() in PLACEHOLDER_EMAIL_LOCAL_PARTS or domain.lower() in PLACEHOLDER_EMAIL_DOMAINS:
            continue
        cleaned.append(e)
    return cleaned


def _is_junk_handle(handle: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", handle.lower())
    if not normalized or len(normalized) < MIN_HANDLE_LENGTH:
        return True
    if normalized in _JUNK_NORMALIZED:
        return True
    if _FILE_EXT_RE.search(handle):
        return True
    return False


def _extract_social_handles(html: str, target_domain: str = "") -> list:
    """target_domain (e.g. 'facebook.com') is used to skip a platform's own
    pattern when the scanned target IS that platform — see
    SOCIAL_PLATFORM_DOMAINS above for why that case can't be filtered by
    word-list alone."""
    results = []
    target_domain = (target_domain or "").lower().lstrip("www.")

    for platform, pattern in SOCIAL_PATTERNS.items():
        platform_domains = SOCIAL_PLATFORM_DOMAINS.get(platform, ())
        if isinstance(platform_domains, str):
            platform_domains = (platform_domains,)
        if target_domain and any(d in target_domain or target_domain in d for d in platform_domains):
            continue  # scanning the platform itself — its own nav isn't a "discovered user"

        for handle in set(pattern.findall(html or "")):
            if _is_junk_handle(handle):
                continue
            results.append({"platform": platform, "handle": handle})
    return results


def _extract_meta_authors(html: str) -> list:
    authors = set()
    for m in re.finditer(
        r'<meta[^>]+name=["\']author["\'][^>]+content=["\']([^"\']+)["\']', html or "", re.I
    ):
        authors.add(m.group(1).strip())
    for m in re.finditer(
        r'"author"\s*:\s*{\s*"@type"\s*:\s*"Person"\s*,\s*"name"\s*:\s*"([^"]+)"', html or ""
    ):
        authors.add(m.group(1).strip())
    return sorted(a for a in authors if a)


def _wp_rest_users(base_url: str, timeout: int) -> list:
    """WordPress exposes a public users list by default at this REST
    endpoint unless the site owner has restricted it — a well-documented
    WordPress recon check, not an exploit."""
    endpoint = urljoin(base_url, "/wp-json/wp/v2/users")
    r = _get(endpoint, timeout)
    users = []
    if r is not None and r.status_code == 200:
        try:
            data = r.json()
            if isinstance(data, list):
                for u in data:
                    users.append({
                        "id": u.get("id"),
                        "username_slug": u.get("slug"),
                        "display_name": u.get("name"),
                        "profile_url": u.get("link"),
                        "source": "wp-json/wp/v2/users",
                    })
        except ValueError:
            pass
    return users


def _wp_author_id_probe(base_url: str, timeout: int, max_id: int = 5) -> list:
    """WordPress redirects /?author=N to /author/<slug>/ for valid users
    by default. Only checks a handful of low IDs — recon, not brute force."""
    found = []
    for author_id in range(1, max_id + 1):
        r = _get(urljoin(base_url, f"/?author={author_id}"), timeout)
        if r is None:
            continue
        m = re.search(r"/author/([^/]+)/?", r.url)
        if m and r.status_code == 200:
            found.append({"id": author_id, "username_slug": m.group(1), "source": "?author=N redirect"})
    return found


def _extract_identities_from_html(html: str, page_path: str, target_domain: str = "") -> list:
    """Runs every content-based extractor (emails, meta authors, social
    handles) against ONE already-fetched page and tags each hit with which
    page it came from."""
    identities = []

    for email in _extract_emails(html):
        identities.append({"type": "email", "value": email, "found_on": page_path})

    for author in _extract_meta_authors(html):
        identities.append({"type": "author_name", "value": author, "found_on": page_path})

    for social in _extract_social_handles(html, target_domain=target_domain):
        identities.append({
            "type": "social_handle",
            "value": social["handle"],
            "platform": social["platform"],
            "found_on": page_path,
        })

    return identities


def _dedupe_identities(identities: list) -> list:
    """Keeps the first sighting of each (type, value[, platform]) — the
    same author email or handle often appears on several pages (homepage
    footer + /contact + /about, etc.)."""
    seen = set()
    deduped = []
    for ident in identities:
        key = (ident["type"], ident["value"].lower(), ident.get("platform"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(ident)
    return deduped


def discover_users(url: str, timeout: int = 10) -> dict:
    """
    Passive recon: collects usernames / author handles / emails / social
    links that the TARGET SITE ITSELF publicly exposes on its own pages.

    Returns a flat, de-duplicated list under "discovered_identities". An
    operator can manually take ONE identifier at a time — only if that
    specific person/account is in scope for the authorized assessment —
    and look it up with the existing osint.py tool. This function never
    calls osint.py or any other lookup itself.
    """
    url = normalize_url(url)
    r = _get(url, timeout)

    if r is None:
        return {"success": False, "url": url, "error": "Request failed (network error)"}

    html = r.text
    final_netloc = urlparse(r.url).netloc
    base = f"{urlparse(r.url).scheme}://{final_netloc}"
    target_domain = final_netloc.split(":")[0]  # strip any port before matching

    identities = _extract_identities_from_html(html, page_path="/ (homepage)", target_domain=target_domain)

    pages_checked = ["/ (homepage)"]
    pages_found = ["/ (homepage)"] if identities else []

    for path in COMMON_PAGES:
        page_r = _get(urljoin(base, path), timeout)
        pages_checked.append(path)
        if page_r is None or page_r.status_code != 200:
            continue
        page_identities = _extract_identities_from_html(page_r.text, page_path=path, target_domain=target_domain)
        if page_identities:
            pages_found.append(path)
        identities.extend(page_identities)

    wp_users = _wp_rest_users(base, timeout)
    for u in wp_users:
        identities.append({
            "type": "username",
            "value": u["username_slug"],
            "display_name": u["display_name"],
            "platform": "WordPress",
            "found_on": u["source"],
        })

    if not wp_users:
        for u in _wp_author_id_probe(base, timeout):
            identities.append({
                "type": "username",
                "value": u["username_slug"],
                "platform": "WordPress",
                "found_on": u["source"],
            })

    identities = _dedupe_identities(identities)

    return {
        "success": True,
        "url": url,
        "final_url": r.url,
        "status_code": r.status_code,
        "pages_checked_count": len(pages_checked),
        "pages_with_hits": pages_found,
        "discovered_identities": identities,
        "identity_count": len(identities),
        "note": (
            "This lists identifiers the TARGET SITE has made public about "
            "itself (author accounts, on-page contact emails, linked social "
            "handles), across the homepage and a handful of common "
            f"same-domain pages ({len(pages_checked)} pages checked). It is "
            "not a profile of any person. Only look an identifier up "
            "further (e.g. with osint.py) if that specific person/account "
            "is in scope for this authorized assessment, and only using "
            "publicly available information."
        ),
    }


def print_discovery_report(result: dict) -> None:
    print("\n" + "=" * 60)
    if not result.get("success"):
        print("USER DISCOVERY FAILED")
        print(f"Error: {result.get('error')}")
        print("=" * 60 + "\n")
        return

    print("EXPOSED USER / IDENTITY DISCOVERY")
    print("=" * 60)
    print(f"Target       : {result['url']}")
    print(f"Status Code  : {result['status_code']}")
    print(f"Pages Checked: {result['pages_checked_count']}")
    print(f"Identities   : {result['identity_count']}")
    print("-" * 60)

    if not result["discovered_identities"]:
        print("  None found.")
    for i, ident in enumerate(result["discovered_identities"], 1):
        platform = f" [{ident['platform']}]" if "platform" in ident else ""
        found_on = f" (found on {ident.get('found_on', '?')})"
        print(f"  {i}. ({ident['type']}){platform}: {ident['value']}{found_on}")

    print("-" * 60)
    print(result["note"])
    print("=" * 60 + "\n")

    if result["discovered_identities"]:
        print("Manual next step — pick ONE in-scope identifier at a time:")
        for ident in result["discovered_identities"]:
            if ident["type"] in ("username", "social_handle"):
                print(f'  python osint.py username search "{ident["value"]}"')
            elif ident["type"] == "email":
                print(f'  python osint.py email analyze "{ident["value"]}"')
        print()


if __name__ == "__main__":
    test_url = input("Enter the URL to scan for exposed users/identities: ")
    res = discover_users(test_url)
    print_discovery_report(res)