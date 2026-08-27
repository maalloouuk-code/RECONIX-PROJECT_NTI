"""
================================================================================
osint_api.py — Programmatic (non-CLI) wrapper around osint.py
================================================================================
osint.py is built as an interactive Typer CLI (Rich tables, prompts). This
module reuses its exact underlying lookup logic — same data sources, same
functions — and returns plain JSON-serializable dicts instead, so app.py can
expose it over HTTP for the frontend's "look up this discovered identity"
button.

Scope notes (read before wiring this into anything else):
  - Every function here takes exactly ONE identifier per call (one
    username, one email, one IP, one phone number). There is no bulk or
    batch lookup here — that mirrors the intended workflow: an operator
    reviews user_discovery.py's results and manually chooses ONE in-scope
    identifier to look up at a time.
  - No new data source is added beyond what osint.py already used: public
    per-site HTTP checks for usernames (same list as osint.py's SITES),
    DNS/MX/SPF/DMARC for email, RDAP + reverse DNS for IP, and
    libphonenumber metadata for phone. This file is a transport wrapper,
    not a new capability.
  - This is meant for an authorized training/assessment environment run
    locally (see app.py) — it is not hardened for exposure on the public
    internet.
================================================================================
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any, Dict, Optional

import osint  # reuses SITES, check_site, get_dns_records, get_rdap, get_reverse_dns, is_valid_ip
import phonenumbers
from phonenumbers import geocoder, carrier
from email_validator import validate_email, EmailNotValidError


async def _run_username_lookup(username: str) -> Dict[str, Any]:
    results = []
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    }
    async with osint.httpx.AsyncClient(headers=headers) as client:
        tasks = [
            osint.check_site(client, site_name, site_data, username)
            for site_name, site_data in osint.SITES.items()
        ]
        for coro in asyncio.as_completed(tasks):
            site_name, url, status = await coro
            results.append({"platform": site_name, "url": url, "status": status})

    # FOUND first, then alphabetical — easiest to scan in the UI.
    results.sort(key=lambda r: (r["status"] != "FOUND", r["platform"]))

    return {
        "success": True,
        "kind": "username",
        "query": username,
        "results": results,
        "found_count": sum(1 for r in results if r["status"] == "FOUND"),
        "checked_count": len(results),
    }


def lookup_username(username: str) -> Dict[str, Any]:
    username = (username or "").strip()
    if not username:
        return {"success": False, "error": "Missing username"}
    return asyncio.run(_run_username_lookup(username))


def lookup_email(email: str) -> Dict[str, Any]:
    email = (email or "").strip()
    if not email:
        return {"success": False, "error": "Missing email"}

    is_valid = False
    normalized = email
    domain = ""
    try:
        valid = validate_email(email, check_deliverability=False)
        normalized = valid.normalized
        domain = valid.domain
        is_valid = True
    except EmailNotValidError:
        if "@" in email:
            domain = email.split("@")[-1]

    if not domain:
        return {"success": False, "error": "Could not determine a domain from that email"}

    async def collect():
        return await asyncio.gather(
            osint.get_dns_records(domain, "MX"),
            osint.get_dns_records(domain, "TXT"),
            osint.get_dns_records(f"_dmarc.{domain}", "TXT"),
        )

    mx_records, txt_records, dmarc_records = asyncio.run(collect())
    spf_found = any("v=spf1" in t.lower() for t in txt_records)
    dmarc_found = any("v=dmarc1" in t.lower() for t in dmarc_records)

    return {
        "success": True,
        "kind": "email",
        "query": email,
        "valid_syntax": is_valid,
        "normalized": normalized,
        "domain": domain,
        "mx_present": bool(mx_records),
        "spf_present": spf_found,
        "dmarc_present": dmarc_found,
    }


def lookup_ip(ip: str) -> Dict[str, Any]:
    ip = (ip or "").strip()
    if not osint.is_valid_ip(ip):
        return {"success": False, "error": "Invalid IP address"}

    addr = ipaddress.ip_address(ip)

    async def collect():
        return await asyncio.gather(osint.get_rdap(ip), osint.get_reverse_dns(ip))

    rdap, rdns = asyncio.run(collect())

    return {
        "success": True,
        "kind": "ip",
        "query": ip,
        "version": f"IPv{addr.version}",
        "public": not addr.is_private,
        "reverse_dns": rdns,
        "asn": rdap.get("asn"),
        "organization": rdap.get("organization"),
    }


def lookup_phone(phone: str, country: Optional[str] = None) -> Dict[str, Any]:
    phone = (phone or "").strip()
    if not phone:
        return {"success": False, "error": "Missing phone number"}

    try:
        parsed = phonenumbers.parse(phone, country)
    except phonenumbers.phonenumberutil.NumberParseException as e:
        return {"success": False, "error": f"Could not parse number: {e}"}

    number_type = phonenumbers.number_type(parsed)
    type_str = {
        phonenumbers.PhoneNumberType.MOBILE: "MOBILE",
        phonenumbers.PhoneNumberType.FIXED_LINE: "FIXED_LINE",
        phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "FIXED_LINE_OR_MOBILE",
    }.get(number_type, "UNKNOWN")

    return {
        "success": True,
        "kind": "phone",
        "query": phone,
        "normalized": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
        "valid": phonenumbers.is_valid_number(parsed),
        "possible": phonenumbers.is_possible_number(parsed),
        "country": geocoder.description_for_number(parsed, "en") or "Unknown",
        "calling_code": f"+{parsed.country_code}",
        "type": type_str,
        "carrier": carrier.name_for_number(parsed, "en") or "Unknown",
    }


def run_lookup(kind: str, value: str, **kwargs) -> Dict[str, Any]:
    """Single dispatch entrypoint used by the Flask blueprint below."""
    kind = (kind or "").strip().lower()
    if kind == "username":
        return lookup_username(value)
    if kind == "email":
        return lookup_email(value)
    if kind == "ip":
        return lookup_ip(value)
    if kind == "phone":
        return lookup_phone(value, country=kwargs.get("country"))
    return {"success": False, "error": f"Unknown lookup kind: {kind}"}


def create_osint_blueprint():
    """
    Mirrors master_link.py's create_master_blueprint() pattern: one
    endpoint per lookup kind, each taking exactly one identifier and
    returning one result. Intentionally no batch endpoint — the frontend
    is expected to call this once per identifier the operator explicitly
    picks from the scan's "Discovered Identities" list.
    """
    try:
        from flask import Blueprint, jsonify, request
    except ImportError:
        return None

    bp = Blueprint("osint_api", __name__)

    def _single_lookup(kind: str):
        data = request.get_json() or {}
        value = data.get("value") or data.get("query")
        if not value:
            return jsonify({"success": False, "error": "Missing 'value' parameter"}), 400
        try:
            result = run_lookup(kind, value, country=data.get("country"))
            status = 200 if result.get("success") else 400
            return jsonify(result), status
        except Exception as e:
            return jsonify({"success": False, "error": f"OSINT lookup failed: {str(e)}"}), 500

    @bp.route("/username", methods=["POST"])
    def username_endpoint():
        return _single_lookup("username")

    @bp.route("/email", methods=["POST"])
    def email_endpoint():
        return _single_lookup("email")

    @bp.route("/ip", methods=["POST"])
    def ip_endpoint():
        return _single_lookup("ip")

    @bp.route("/phone", methods=["POST"])
    def phone_endpoint():
        return _single_lookup("phone")

    @bp.route("/health", methods=["GET"])
    def health():
        return jsonify({
            "module": "OSINT Lookup API (username / email / ip / phone) — single-identifier only",
            "status": "operational",
        }), 200

    return bp