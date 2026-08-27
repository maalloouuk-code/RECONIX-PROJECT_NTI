import time
import requests
from requests.exceptions import (
    RequestException,
    ConnectionError,
    Timeout,
    MissingSchema,
    InvalidURL,
)
from urllib.parse import urlparse

DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (SecurityScanner/1.0)"}
RISKY_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT"}

# Weight used to turn a severity into a score penalty.
# Higher = more impact on the final score.
SEVERITY_WEIGHT = {"High": 3, "Medium": 2, "Low": 1, "Info": 0}

SCAN_LIMITATIONS = [
    "This scan only inspects the raw HTTP response (via Python 'requests'). "
    "It does not execute JavaScript, so cookies or headers set dynamically "
    "by client-side scripts will not be detected.",
    "The scan is unauthenticated. Pages or protections that only appear "
    "after login are not covered.",
    "Allowed HTTP methods are detected via the 'Allow' header returned by "
    "an OPTIONS request. This does NOT confirm the methods are actually "
    "exploitable — it only means the server advertises support for them. "
    "Manual verification is required before treating this as a confirmed risk.",
    "A 200 status code only means the server responded successfully to the "
    "request — it does not mean the site passed any security check.",
    "This is an automated surface-level scan, not a full penetration test "
    "or security audit.",
]


def normalize_url(url: str) -> str:
    """
    If the user enters a URL without http:// or https://,
    automatically prepend https:// so the request doesn't fail.
    """
    url = url.strip()
    if not urlparse(url).scheme:
        url = "https://" + url
    return url


# ======================================================================
# NETWORK CAPTURE LAYER
# ======================================================================
# This is the ONLY place in the whole toolkit that is allowed to talk to
# the network. Every other module/function (the checks below, as well as
# security_behavior_engine.py via master_link.py) works off the data
# captured here instead of independently re-fetching the target. That
# keeps http_scanner.py responsible for "get the data" and lets the
# other files stay responsible for "analyze the data".
def _extract_raw_cookies(response) -> list:
    """
    `response.headers` merges multiple 'Set-Cookie' lines into one string,
    which breaks cookie-by-cookie analysis. Going through the underlying
    urllib3 raw headers gets every individual Set-Cookie line instead.
    """
    try:
        raw = response.raw.headers.getlist("Set-Cookie")
        if raw:
            return list(raw)
    except Exception:
        pass
    single = response.headers.get("Set-Cookie")
    return [single] if single else []


def _probe(method: str, url: str, timeout: int, headers: dict = None,
           allow_redirects: bool = False) -> dict:
    """
    Single low-level HTTP call shared by every probe below, in a shape
    compatible with the rest of the toolkit (success/status_code/headers/
    raw_cookies/latency_ms/error). Keeps the raw `requests.Response` under
    the private "_response" key for internal reuse only; callers outside
    this module should use capture_network_data(), which strips it.
    """
    req_headers = dict(DEFAULT_HEADERS)
    if headers:
        req_headers.update(headers)

    start = time.time()
    try:
        response = requests.request(
            method, url, timeout=timeout,
            allow_redirects=allow_redirects, headers=req_headers,
        )
        return {
            "success": True,
            "url": url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "raw_cookies": _extract_raw_cookies(response),
            "latency_ms": round((time.time() - start) * 1000, 2),
            "error": None,
            "_response": response,
        }
    except RequestException as e:
        return {
            "success": False,
            "url": url,
            "status_code": 0,
            "headers": {},
            "raw_cookies": [],
            "latency_ms": round((time.time() - start) * 1000, 2),
            "error": str(e),
        }


def _strip_internal(capture: dict) -> dict:
    """Returns a JSON-safe copy of a capture dict (no raw response objects)."""
    clean = {}
    for key, value in capture.items():
        if isinstance(value, dict) and "_response" in value:
            value = {k: v for k, v in value.items() if k != "_response"}
        clean[key] = value
    return clean


def _capture(url: str, timeout: int = 10) -> dict:
    """
    Performs every network request the toolkit needs against the target,
    ONE time each: the main GET (with redirects followed), separate plain
    HTTP/HTTPS probes (no redirects, used to check transport enforcement),
    an OPTIONS probe, a TRACE probe, and a spoofed-Origin probe for CORS.
    Keeps raw `requests.Response` objects internally so run_full_scan()
    can build its detailed findings without firing any extra requests.
    """
    url = normalize_url(url)
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port_suffix = f":{parsed.port}" if parsed.port else ""

    http_url = f"http://{host}{port_suffix}" if parsed.scheme == "http" else f"http://{host}"
    https_url = f"https://{host}{port_suffix}" if parsed.scheme == "https" else f"https://{host}"

    main = _probe("GET", url, timeout, allow_redirects=True)

    final_url = url
    redirect_chain = []
    if main.get("success") and main.get("_response") is not None:
        response = main["_response"]
        final_url = response.url
        hops = list(response.history) + [response]
        for i in range(len(hops) - 1):
            src, dst = hops[i], hops[i + 1]
            src_scheme = urlparse(src.url).scheme
            dst_scheme = urlparse(dst.url).scheme
            if src_scheme == "http" and dst_scheme == "https":
                protocol_change = "UPGRADE_TO_HTTPS"
            elif src_scheme == "https" and dst_scheme == "http":
                protocol_change = "DOWNGRADE_TO_HTTP"
            else:
                protocol_change = "NONE"
            redirect_chain.append({
                "step": i + 1,
                "status_code": src.status_code,
                "source_url": src.url,
                "destination_url": dst.url,
                "protocol_change": protocol_change,
                "host_change": urlparse(src.url).hostname != urlparse(dst.url).hostname,
                "latency_ms": 0.0,
            })

    http_probe = _probe("GET", http_url, timeout, allow_redirects=False)
    https_probe = _probe("GET", https_url, timeout, allow_redirects=False)
    options_response = _probe("OPTIONS", url, timeout, allow_redirects=False)
    try:
        trace_response = _probe("TRACE", url, timeout, allow_redirects=False)
    except Exception as e:
        trace_response = {"success": False, "url": url, "status_code": 0,
                           "headers": {}, "raw_cookies": [], "latency_ms": 0.0,
                           "error": str(e)}
    origin_probe = _probe(
        "GET", url, timeout, allow_redirects=False,
        headers={"Origin": "https://security-profiler.academic-test.org"},
    )

    return {
        "success": main.get("success", False),
        "requested_url": url,
        "final_url": final_url,
        "error": main.get("error"),
        "main": main,
        "http_probe": http_probe,
        "https_probe": https_probe,
        "options_response": options_response,
        "trace_response": trace_response,
        "origin_probe": origin_probe,
        "redirect_chain": redirect_chain,
    }


def capture_network_data(url: str, timeout: int = 10) -> dict:
    """
    Public, JSON-safe version of _capture(): everything downstream
    (security_behavior_engine.py, master_link.py, or any other consumer)
    should call this instead of fetching the target itself.
    """
    return _strip_internal(_capture(url, timeout=timeout))


def make_finding(check, status, finding_type, confidence, severity,
                  recommendation, details=None):
    """
    Standard shape for every finding across all 3 modules.
    """
    return {
        "check": check,
        "status": status,
        "finding_type": finding_type,   # "Security Finding" | "Information"
        "confidence": confidence,       # "Confirmed" | "Suspected" | "Needs Manual Verification"
        "severity": severity,           # "High" | "Medium" | "Low" | "Info"
        "details": details or {},
        "recommendation": recommendation,
    }


# ======================================================================
# 1. HTTP SCANNER
# ======================================================================
def scan_http(url: str, timeout: int = 10) -> dict:
    """
    Performs the base HTTP scan: status code, headers, cookies, redirects.
    """
    url = normalize_url(url)

    try:
        start_time = time.time()

        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers=DEFAULT_HEADERS,
        )

        elapsed_time = round(time.time() - start_time, 3)

        redirect_chain = []
        for r in response.history:
            redirect_chain.append({
                "url": r.url,
                "status_code": r.status_code,
                "location": r.headers.get("Location", ""),
            })

        cookies_list = []
        for cookie in response.cookies:
            cookies_list.append({
                "name": cookie.name,
                "value": cookie.value,
                "domain": cookie.domain,
                "path": cookie.path,
                "secure": cookie.secure,
                "httponly": "httponly" in [k.lower() for k in cookie._rest.keys()],
                "samesite": cookie._rest.get("SameSite", None),
                "expires": cookie.expires,
            })

        return {
            "success": True,
            "requested_url": url,
            "final_url": response.url,
            "status_code": response.status_code,
            "status_note": "Server responded successfully. This does NOT "
                            "imply the site is secure.",
            "response_time_seconds": elapsed_time,
            "headers": dict(response.headers),
            "cookies": cookies_list,
            "redirected": len(redirect_chain) > 0,
            "redirect_count": len(redirect_chain),
            "redirect_chain": redirect_chain,
        }

    except MissingSchema:
        return {"success": False, "error": "Invalid URL format"}
    except InvalidURL:
        return {"success": False, "error": "Invalid URL"}
    except ConnectionError:
        return {"success": False, "error": "Could not connect to the server (Connection Error)"}
    except Timeout:
        return {"success": False, "error": "Connection timed out (Timeout)"}
    except RequestException as e:
        return {"success": False, "error": f"Unexpected error occurred: {str(e)}"}


# ======================================================================
# 2. SECURITY HEADERS
# ======================================================================
# NOTE on severities: these reflect *typical* impact when a header is
# completely absent on a public page. Real-world impact always depends
# on the site's context (e.g. a site with no third-party embeds cares
# less about Referrer-Policy). Treat these as defaults, not universal law.
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "High",
        "recommendation": "Add a Content-Security-Policy header to restrict which "
                           "sources scripts, styles, and other resources can be "
                           "loaded from, to help prevent XSS attacks.",
    },
    "Strict-Transport-Security": {
        "severity": "High",
        "recommendation": "Add a Strict-Transport-Security (HSTS) header to force "
                           "browsers to only connect over HTTPS, e.g. "
                           "'max-age=31536000; includeSubDomains'.",
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "recommendation": "Add an X-Frame-Options header (e.g. 'DENY' or "
                           "'SAMEORIGIN') to protect against clickjacking attacks.",
    },
    "X-Content-Type-Options": {
        "severity": "Medium",
        "recommendation": "Add 'X-Content-Type-Options: nosniff' to stop browsers "
                           "from MIME-sniffing a response away from the declared "
                           "content-type.",
    },
    "Referrer-Policy": {
        # Downgraded: absence is a low-impact hardening gap in most cases,
        # not a direct vulnerability. Real impact depends on the site.
        "severity": "Low",
        "recommendation": "Consider adding a Referrer-Policy header (e.g. "
                           "'strict-origin-when-cross-origin') to limit how much "
                           "referrer information leaks to other sites. Impact "
                           "depends on what sensitive data (if any) appears in URLs.",
    },
    "Permissions-Policy": {
        "severity": "Low",
        "recommendation": "Add a Permissions-Policy header to control which "
                           "browser features (camera, microphone, geolocation...) "
                           "the page is allowed to use.",
    },
}


def _check_security_headers_from_data(response_headers_raw: dict) -> list:
    """
    Pure analysis: checks an already-fetched headers dict against the
    SECURITY_HEADERS list. Makes no network calls.
    """
    response_headers = {k.lower(): v for k, v in response_headers_raw.items()}
    findings = []

    for header_name, meta in SECURITY_HEADERS.items():
        key = header_name.lower()
        present = key in response_headers

        if present:
            findings.append(make_finding(
                check=header_name,
                status="Present",
                finding_type="Information",
                confidence="Confirmed",
                severity="Info",
                recommendation="OK - header is set correctly.",
                details={"value": response_headers.get(key)},
            ))
        else:
            findings.append(make_finding(
                check=header_name,
                status="Missing",
                finding_type="Security Finding",
                confidence="Confirmed",
                severity=meta["severity"],
                recommendation=meta["recommendation"],
            ))

    return findings


def check_security_headers(url: str, timeout: int = 10) -> dict:
    """
    Standalone helper: fetches the URL itself and checks it against the
    SECURITY_HEADERS list. Kept for direct/CLI use; run_full_scan() does
    NOT call this anymore — it reuses the single shared capture instead
    (see _check_security_headers_from_data).
    """
    url = normalize_url(url)

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers=DEFAULT_HEADERS,
        )

        response_headers = {k.lower(): v for k, v in response.headers.items()}

        findings = []

        for header_name, meta in SECURITY_HEADERS.items():
            key = header_name.lower()
            present = key in response_headers

            if present:
                findings.append(make_finding(
                    check=header_name,
                    status="Present",
                    finding_type="Information",
                    confidence="Confirmed",
                    severity="Info",
                    recommendation="OK - header is set correctly.",
                    details={"value": response_headers.get(key)},
                ))
            else:
                findings.append(make_finding(
                    check=header_name,
                    status="Missing",
                    finding_type="Security Finding",
                    confidence="Confirmed",
                    severity=meta["severity"],
                    recommendation=meta["recommendation"],
                ))

        score = _weighted_score(findings)

        return {
            "success": True,
            "requested_url": url,
            "final_url": response.url,
            "status_code": response.status_code,
            "score_percent": score,
            "findings": findings,
        }

    except MissingSchema:
        return {"success": False, "error": "Invalid URL format"}
    except InvalidURL:
        return {"success": False, "error": "Invalid URL"}
    except ConnectionError:
        return {"success": False, "error": "Could not connect to the server (Connection Error)"}
    except Timeout:
        return {"success": False, "error": "Connection timed out (Timeout)"}
    except RequestException as e:
        return {"success": False, "error": f"Unexpected error occurred: {str(e)}"}


# ======================================================================
# 3. COOKIES & CONFIGURATION
# ======================================================================
def _check_cookies(response) -> list:
    """
    Only generates findings for cookies that ARE present. If the server
    sets no cookies on this response, that's not reported as a finding
    at all (it's neither good nor bad — cookies may be set later, via
    JS, or not needed).
    """
    findings = []

    for cookie in response.cookies:
        rest_keys = [k.lower() for k in cookie._rest.keys()]
        samesite = cookie._rest.get("SameSite", None)
        httponly = "httponly" in rest_keys

        issues = []
        if not cookie.secure:
            issues.append("missing 'Secure' flag")
        if not httponly:
            issues.append("missing 'HttpOnly' flag")
        if not samesite:
            issues.append("missing 'SameSite' attribute")
        elif samesite.lower() == "none" and not cookie.secure:
            issues.append("'SameSite=None' without 'Secure' flag")

        details = {
            "domain": cookie.domain,
            "path": cookie.path,
            "secure": cookie.secure,
            "httponly": httponly,
            "samesite": samesite,
        }

        if issues:
            severity = "High" if ("missing 'Secure' flag" in issues or
                                   "missing 'HttpOnly' flag" in issues) else "Medium"
            findings.append(make_finding(
                check=f"Cookie: {cookie.name}",
                status="Issues Found",
                finding_type="Security Finding",
                confidence="Confirmed",
                severity=severity,
                recommendation=f"Cookie '{cookie.name}' should set: " + ", ".join(issues) + ".",
                details=details,
            ))
        else:
            findings.append(make_finding(
                check=f"Cookie: {cookie.name}",
                status="OK",
                finding_type="Information",
                confidence="Confirmed",
                severity="Info",
                recommendation="OK - cookie is configured securely.",
                details=details,
            ))

    return findings


def _check_server_info(headers: dict) -> list:
    """
    Informational only. Disclosing a Server/X-Powered-By header is a
    minor information-disclosure practice, not a vulnerability by itself
    — it does not get scored as a Security Finding.
    """
    findings = []
    disclosure_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]

    for header in disclosure_headers:
        value = headers.get(header)
        if value:
            findings.append(make_finding(
                check=f"Header: {header}",
                status="Disclosed",
                finding_type="Information",
                confidence="Confirmed",
                severity="Low",
                recommendation=f"'{header}' header discloses '{value}'. This is a minor "
                                f"information-disclosure practice, not a vulnerability on "
                                f"its own — but it does make reconnaissance slightly easier "
                                f"for an attacker. Optional to mask.",
                details={"value": value},
            ))
        # NOTE: we no longer create a finding when the header is absent —
        # "not disclosed" is a neutral default, not an achievement.

    return findings


def _check_http_methods_from_data(options_response: dict) -> dict:
    """
    Pure analysis version of _check_http_methods(): reads an already-
    captured OPTIONS response instead of sending a new OPTIONS request.
    """
    if not options_response or not options_response.get("success"):
        return make_finding(
            check="HTTP Methods",
            status="Unknown",
            finding_type="Information",
            confidence="Needs Manual Verification",
            severity="Info",
            recommendation="Could not determine allowed HTTP methods "
                            "(OPTIONS request failed).",
        )

    allow_header = options_response.get("headers", {}).get("Allow", "")
    methods = [m.strip().upper() for m in allow_header.split(",") if m.strip()]
    risky_found = [m for m in methods if m in RISKY_METHODS]

    if not methods:
        return make_finding(
            check="HTTP Methods",
            status="Unknown",
            finding_type="Information",
            confidence="Needs Manual Verification",
            severity="Info",
            recommendation="Server did not return an 'Allow' header for "
                            "OPTIONS requests. Method support is unknown.",
            details={"allowed_methods": []},
        )

    if risky_found:
        return make_finding(
            check="HTTP Methods",
            status="Risky Methods Advertised",
            finding_type="Security Finding",
            confidence="Suspected",
            severity="Medium",
            recommendation=(
                f"The server advertises support for {', '.join(risky_found)} "
                f"via the OPTIONS 'Allow' header. This does NOT confirm these "
                f"methods are actually usable or dangerous on this specific "
                f"endpoint — many servers advertise methods generically. "
                f"Manually verify (e.g. send an actual PUT/DELETE request and "
                f"check the real response/effect) before treating this as a "
                f"confirmed vulnerability. If genuinely unnecessary, disable them."
            ),
            details={"allowed_methods": methods},
        )

    return make_finding(
        check="HTTP Methods",
        status="OK",
        finding_type="Information",
        confidence="Confirmed",
        severity="Info",
        recommendation="OK - no risky HTTP methods advertised.",
        details={"allowed_methods": methods},
    )


def _check_http_methods(url: str, timeout: int) -> dict:
    """
    Uses OPTIONS to see which methods the server *advertises*. This is
    NOT proof those methods are actually reachable/exploitable on this
    endpoint — servers commonly advertise methods generically at the
    edge/load-balancer level. Marked as "Suspected" and excluded from
    the score until manually verified.
    """
    try:
        response = requests.options(url, timeout=timeout, headers=DEFAULT_HEADERS)
        allow_header = response.headers.get("Allow", "")
        methods = [m.strip().upper() for m in allow_header.split(",") if m.strip()]

        risky_found = [m for m in methods if m in RISKY_METHODS]

        if not methods:
            return make_finding(
                check="HTTP Methods",
                status="Unknown",
                finding_type="Information",
                confidence="Needs Manual Verification",
                severity="Info",
                recommendation="Server did not return an 'Allow' header for "
                                "OPTIONS requests. Method support is unknown.",
                details={"allowed_methods": []},
            )

        if risky_found:
            return make_finding(
                check="HTTP Methods",
                status="Risky Methods Advertised",
                finding_type="Security Finding",
                confidence="Suspected",  # <-- not confirmed exploitable
                severity="Medium",
                recommendation=(
                    f"The server advertises support for {', '.join(risky_found)} "
                    f"via the OPTIONS 'Allow' header. This does NOT confirm these "
                    f"methods are actually usable or dangerous on this specific "
                    f"endpoint — many servers advertise methods generically. "
                    f"Manually verify (e.g. send an actual PUT/DELETE request and "
                    f"check the real response/effect) before treating this as a "
                    f"confirmed vulnerability. If genuinely unnecessary, disable them."
                ),
                details={"allowed_methods": methods},
            )

        return make_finding(
            check="HTTP Methods",
            status="OK",
            finding_type="Information",
            confidence="Confirmed",
            severity="Info",
            recommendation="OK - no risky HTTP methods advertised.",
            details={"allowed_methods": methods},
        )

    except RequestException:
        return make_finding(
            check="HTTP Methods",
            status="Unknown",
            finding_type="Information",
            confidence="Needs Manual Verification",
            severity="Info",
            recommendation="Could not determine allowed HTTP methods "
                            "(OPTIONS request failed).",
        )


def _check_redirects(response) -> dict:
    redirect_chain = []
    insecure_redirect = False

    for r in response.history:
        redirect_chain.append({
            "url": r.url,
            "status_code": r.status_code,
            "location": r.headers.get("Location", ""),
        })
        if r.url.startswith("http://"):
            insecure_redirect = True

    if not redirect_chain:
        return make_finding(
            check="Redirects",
            status="No Redirects",
            finding_type="Information",
            confidence="Confirmed",
            severity="Info",
            recommendation="No redirects occurred on this request.",
        )

    if insecure_redirect:
        return make_finding(
            check="Redirects",
            status="Insecure Redirect Detected",
            finding_type="Security Finding",
            confidence="Confirmed",
            severity="Medium",
            recommendation="The site is reachable over plain HTTP before "
                            "redirecting. Enforce HTTPS at the server/load "
                            "balancer level and add HSTS.",
            details={"redirect_chain": redirect_chain},
        )

    return make_finding(
        check="Redirects",
        status="OK",
        finding_type="Information",
        confidence="Confirmed",
        severity="Info",
        recommendation="OK - all redirects use HTTPS.",
        details={"redirect_chain": redirect_chain},
    )


def check_cookies_and_config(url: str, timeout: int = 10) -> dict:
    """
    Checks cookies (Secure/HttpOnly/SameSite) that are actually present,
    server info disclosure (informational), allowed HTTP methods
    (suspected, needs manual verification), and redirect chain security.
    """
    url = normalize_url(url)

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers=DEFAULT_HEADERS,
        )

        findings = []
        findings.extend(_check_cookies(response))
        findings.extend(_check_server_info(response.headers))
        findings.append(_check_http_methods(url, timeout))
        findings.append(_check_redirects(response))

        score = _weighted_score(findings)

        return {
            "success": True,
            "requested_url": url,
            "final_url": response.url,
            "status_code": response.status_code,
            "cookies_found": len(response.cookies),
            "cookies_note": "0 cookies found simply means none were set on this "
                             "specific request/response. It is not treated as a "
                             "negative finding.",
            "score_percent": score,
            "findings": findings,
        }

    except MissingSchema:
        return {"success": False, "error": "Invalid URL format"}
    except InvalidURL:
        return {"success": False, "error": "Invalid URL"}
    except ConnectionError:
        return {"success": False, "error": "Could not connect to the server (Connection Error)"}
    except Timeout:
        return {"success": False, "error": "Connection timed out (Timeout)"}
    except RequestException as e:
        return {"success": False, "error": f"Unexpected error occurred: {str(e)}"}


# ======================================================================
# SCORING
# ======================================================================
def _weighted_score(findings: list) -> int:
    """
    Score is based ONLY on findings where:
      - finding_type == "Security Finding"
      - confidence == "Confirmed"
    (Information items and Suspected/Needs-Verification items never
    affect the score — they're shown for awareness, not penalized.)

    Formula: start at 100, subtract a fixed point penalty per confirmed
    security finding based on its severity weight (High=25, Medium=15,
    Low=5). Issues stack additively, capped at 0.

    This is a simple, transparent point-deduction model rather than a
    pass/fail ratio, so a single High-severity issue doesn't
    automatically zero the whole score the way a ratio-based model
    would when there are few total checks.
    """
    penalty_per_weight = {3: 25, 2: 15, 1: 5}  # High/Medium/Low point deduction each
    score = 100
    for f in findings:
        if f["finding_type"] == "Security Finding" and f["confidence"] == "Confirmed":
            weight = SEVERITY_WEIGHT.get(f["severity"], 1)
            score -= penalty_per_weight.get(weight, 5)
    return max(0, score)


# ======================================================================
# COMBINED SCAN (this is what the Flask backend should call)
# ======================================================================
def run_full_scan(url: str, timeout: int = 10) -> dict:
    """
    Runs the full scan against the target — fetching it ONLY ONCE per
    probe type (main GET, HTTP/HTTPS probes, OPTIONS, TRACE, Origin) via
    _capture() — then runs every analysis (headers, cookies, methods,
    redirects) on that single captured dataset. Also embeds the raw
    capture under "network_capture" so master_link.py can pass it
    straight to security_behavior_engine.py without re-fetching the
    target a second time.
    """
    url = normalize_url(url)

    capture = _capture(url, timeout=timeout)
    main = capture["main"]

    if not main.get("success"):
        return {
            "success": False,
            "url": url,
            "error": main.get("error", "Unknown error"),
        }

    response = main["_response"]
    elapsed_time = main["latency_ms"] / 1000.0

    cookies_list = []
    for cookie in response.cookies:
        cookies_list.append({
            "name": cookie.name,
            "value": cookie.value,
            "domain": cookie.domain,
            "path": cookie.path,
            "secure": cookie.secure,
            "httponly": "httponly" in [k.lower() for k in cookie._rest.keys()],
            "samesite": cookie._rest.get("SameSite", None),
            "expires": cookie.expires,
        })

    redirect_chain_legacy = [
        {"url": r.url, "status_code": r.status_code, "location": r.headers.get("Location", "")}
        for r in response.history
    ]

    http_result = {
        "success": True,
        "requested_url": url,
        "final_url": response.url,
        "status_code": response.status_code,
        "status_note": "Server responded successfully. This does NOT "
                        "imply the site is secure.",
        "response_time_seconds": round(elapsed_time, 3),
        "headers": main["headers"],
        "cookies": cookies_list,
        "redirected": len(redirect_chain_legacy) > 0,
        "redirect_count": len(redirect_chain_legacy),
        "redirect_chain": redirect_chain_legacy,
    }

    headers_findings = _check_security_headers_from_data(main["headers"])
    headers_result = {
        "success": True,
        "requested_url": url,
        "final_url": response.url,
        "status_code": response.status_code,
        "score_percent": _weighted_score(headers_findings),
        "findings": headers_findings,
    }

    cookie_findings = []
    cookie_findings.extend(_check_cookies(response))
    cookie_findings.extend(_check_server_info(main["headers"]))
    cookie_findings.append(_check_http_methods_from_data(capture["options_response"]))
    cookie_findings.append(_check_redirects(response))

    cookies_result = {
        "success": True,
        "requested_url": url,
        "final_url": response.url,
        "status_code": response.status_code,
        "cookies_found": len(response.cookies),
        "cookies_note": "0 cookies found simply means none were set on this "
                         "specific request/response. It is not treated as a "
                         "negative finding.",
        "score_percent": _weighted_score(cookie_findings),
        "findings": cookie_findings,
    }

    all_findings = []
    if headers_result.get("success"):
        all_findings.extend(headers_result["findings"])
    if cookies_result.get("success"):
        all_findings.extend(cookies_result["findings"])

    confirmed_security_findings = [
        f for f in all_findings
        if f["finding_type"] == "Security Finding" and f["confidence"] == "Confirmed"
    ]
    suspected_findings = [f for f in all_findings if f["confidence"] == "Suspected"]
    needs_verification_findings = [
        f for f in all_findings if f["confidence"] == "Needs Manual Verification"
    ]
    # "Information" items that are also unverified are shown only under
    # needs_manual_verification, to avoid listing the same check twice.
    informational_findings = [
        f for f in all_findings
        if f["finding_type"] == "Information" and f["confidence"] == "Confirmed"
    ]

    scores = []
    if headers_result.get("success"):
        scores.append(headers_result["score_percent"])
    if cookies_result.get("success"):
        scores.append(cookies_result["score_percent"])
    overall_score = round(sum(scores) / len(scores)) if scores else 0

    return {
        "success": True,
        "url": url,
        "http_scan": http_result,
        "security_headers": headers_result,
        "cookies_config": cookies_result,
        "overall_score_percent": overall_score,
        "score_note": "Score only reflects Confirmed Security Findings "
                       "(weighted by severity). Suspected items and "
                       "Information items are excluded and shown separately.",
        "all_findings": all_findings,
        "confirmed_security_findings": confirmed_security_findings,
        "suspected_findings": suspected_findings,
        "needs_manual_verification": needs_verification_findings,
        "informational_findings": informational_findings,
        "scan_limitations": SCAN_LIMITATIONS,
        # Raw, already-fetched network data (JSON-safe). Pass this to
        # security_behavior_engine.analyze_scan_data() so it can run its
        # analysis without sending any requests of its own.
        "network_capture": _strip_internal(capture),
    }


# ======================================================================
# PRINT HELPER
# ======================================================================
def print_result(result: dict) -> None:
    print("\n" + "=" * 60)

    if not result.get("success"):
        print("SCAN FAILED")
        print("-" * 60)
        print(f"Error: {result.get('error')}")
        print("=" * 60 + "\n")
        return

    print("FULL SECURITY SCAN RESULT")
    print("=" * 60)
    print(f"URL                : {result['url']}")
    print(f"Status Code        : {result['http_scan']['status_code']} "
          f"({result['http_scan']['status_note']})")
    print(f"Response Time      : {result['http_scan']['response_time_seconds']} seconds")
    print(f"Overall Score      : {result['overall_score_percent']}%  "
          f"({result['score_note']})")

    print("\n--- Confirmed Security Findings ---")
    if result["confirmed_security_findings"]:
        for f in result["confirmed_security_findings"]:
            print(f"  [CONFIRMED] {f['check']} | Severity: {f['severity']}")
            print(f"      {f['recommendation']}")
    else:
        print("  None.")

    print("\n--- Suspected (needs manual verification before treating as a risk) ---")
    if result["suspected_findings"]:
        for f in result["suspected_findings"]:
            print(f"  [SUSPECTED] {f['check']} | Severity: {f['severity']}")
            print(f"      {f['recommendation']}")
    else:
        print("  None.")

    print("\n--- Needs Manual Verification (inconclusive) ---")
    if result["needs_manual_verification"]:
        for f in result["needs_manual_verification"]:
            print(f"  [UNVERIFIED] {f['check']}")
            print(f"      {f['recommendation']}")
    else:
        print("  None.")

    print("\n--- Informational (not scored) ---")
    for f in result["informational_findings"]:
        print(f"  [INFO] {f['check']}: {f['status']}")

    print("\n--- Scan Limitations ---")
    for note in result["scan_limitations"]:
        print(f"  - {note}")

    print("=" * 60 + "\n")


if __name__ == "__main__":
    test_url = input("Enter the URL you want to scan: ")
    result = run_full_scan(test_url)
    print_result(result)