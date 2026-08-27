from __future__ import annotations

import json
import os
from datetime import datetime
from time import perf_counter
from typing import Any, Dict

import security_behavior_engine as behavior_engine
import http_scanner as scanner
import robots_analyzer as robots
import user_discovery



def run_behavior_engine_from_capture(network_capture: Dict[str, Any], timeout: float = 6.0) -> Dict[str, Any]:
    """
    Runs the behavior engine's analysis on data that was ALREADY fetched
    by http_scanner.py (see run_http_scanner below). Makes no network
    calls of its own — http_scanner.py is the only module in this toolkit
    that talks to the network.
    """
    try:
        profiler = behavior_engine.SecurityBehaviorProfiler(
            timeout=timeout, verify_ssl=True
        )
        report = profiler.analyze_scan_data(network_capture)
        return {"success": True, "report": report.to_dict()}
    except Exception as e:
        return {"success": False, "error": f"Behavior engine failed: {str(e)}"}


def run_http_scanner(url: str, timeout: int = 10) -> Dict[str, Any]:
    """
    The ONLY function in this toolkit that fetches the target. It returns
    the combined scanner result plus the raw "network_capture" that
    run_behavior_engine_from_capture() reuses, so the target is never
    fetched twice.
    """
    try:
        return scanner.run_full_scan(url, timeout=timeout)
    except Exception as e:
        return {"success": False, "error": f"Combined scanner failed: {str(e)}"}


def run_user_discovery(url: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Passive-only: lists usernames/emails/social handles the TARGET SITE
    itself exposes on its own pages (WordPress authors, meta/JSON-LD
    author tags, on-page emails, linked social profiles). Does not call
    osint.py or look anyone up — that stays a separate, manual, one-at-a-
    time step the operator takes via the /api/v1/osint endpoints, only for
    identifiers that are actually in scope for this assessment.
    """
    try:
        return user_discovery.discover_users(url, timeout=timeout)
    except Exception as e:
        return {"success": False, "error": f"User discovery failed: {str(e)}"}


def run_robots_analysis(url: str, timeout: int = 10) -> Dict[str, Any]:
    try:
        base = robots.normalize_url(url)
    except ValueError:
        return {"success": False, "error": "Invalid URL for robots.txt check"}

    response = robots.get_robots(base)

    if response is None:
        return {"success": False, "error": "robots.txt request failed (network error)"}

    status = response.status_code

    if status != 200:
        return {
            "success": True,
            "robots_found": False,
            "status_code": status,
            "target": base,
            "robots_url": base.rstrip("/") + "/robots.txt",
            "note": {
                403: "robots.txt access forbidden (HTTP 403)",
                404: "robots.txt not found (HTTP 404)",
            }.get(status, f"Unexpected HTTP status: {status}"),
        }

    data = robots.analyze_robots(response.text)
    interesting_paths = robots.detect_interesting_paths(data["disallow"])

    return {
        "success": True,
        "robots_found": True,
        "status_code": status,
        "target": base,
        "robots_url": base.rstrip("/") + "/robots.txt",
        "user_agents": data["user_agents"],
        "disallowed_paths": data["disallow"],
        "allowed_paths": data["allow"],
        "sitemaps": data["sitemaps"],
        "interesting_paths": interesting_paths,
        "summary": {
            "user_agents_count": len(data["user_agents"]),
            "disallowed_count": len(data["disallow"]),
            "allowed_count": len(data["allow"]),
            "sitemaps_count": len(data["sitemaps"]),
            "interesting_paths_count": len(interesting_paths),
        },
    }

def _compute_unified_score(
    behavior_result: Dict[str, Any],
    scanner_result: Dict[str, Any],
    robots_result: Dict[str, Any],
) -> Dict[str, Any]:
   
    scores, weights = [], []

    if behavior_result.get("success"):
        scores.append(behavior_result["report"]["overall"]["score"])
        weights.append(0.6)

    if scanner_result.get("success"):
        scores.append(scanner_result["overall_score_percent"])
        weights.append(0.4)

    weighted = (
        sum(s * w for s, w in zip(scores, weights)) / sum(weights)
        if scores else 0
    )

    high_risk_paths = 0
    if robots_result.get("success") and robots_result.get("robots_found"):
        high_risk_paths = sum(
            1 for p in robots_result.get("interesting_paths", [])
            if p["severity"] == "High"
        )
    robots_penalty = min(10, high_risk_paths * 3)

    final_score = max(0, round(weighted - robots_penalty))

    if final_score >= 90:
        rating = "Excellent"
    elif final_score >= 75:
        rating = "Good"
    elif final_score >= 50:
        rating = "Fair"
    elif final_score >= 25:
        rating = "Poor"
    else:
        rating = "Critical"

    return {
        "unified_score_percent": final_score,
        "rating": rating,
        "components": {
            "behavior_engine_score": (
                behavior_result["report"]["overall"]["score"]
                if behavior_result.get("success") else None
            ),
            "combined_scanner_score": (
                scanner_result.get("overall_score_percent")
                if scanner_result.get("success") else None
            ),
            "robots_high_risk_paths_penalty": robots_penalty,
            "robots_high_risk_paths_count": high_risk_paths,
        },
    }

def run_master_scan(url: str, timeout: float = 10.0) -> Dict[str, Any]:

    started = perf_counter()

    # http_scanner.py fetches the target ONCE (main GET + HTTP/HTTPS/
    # OPTIONS/TRACE/Origin probes) and returns both its own findings and
    # the raw "network_capture". The behavior engine then analyzes that
    # same capture instead of fetching the target again itself.
    scanner_result = run_http_scanner(url, timeout=int(timeout))

    if scanner_result.get("success") and "network_capture" in scanner_result:
        behavior_result = run_behavior_engine_from_capture(
            scanner_result["network_capture"], timeout=timeout
        )
    else:
        behavior_result = {
            "success": False,
            "error": f"Behavior engine skipped: HTTP scanner failed "
                     f"({scanner_result.get('error', 'unknown error')})",
        }

    robots_result = run_robots_analysis(url, timeout=int(timeout))
    user_discovery_result = run_user_discovery(url, timeout=int(timeout))

    unified = _compute_unified_score(behavior_result, scanner_result, robots_result)

    # A "0% CRITICAL" score should only ever mean "we scanned it and it's
    # genuinely bad" — never "we couldn't scan it at all". If neither of the
    # two modules that feed the score succeeded, flag it explicitly so the
    # frontend can show a real error instead of a misleading fake result.
    core_modules_failed = not behavior_result.get("success") and not scanner_result.get("success")

    return {
        "target": url,
        "scan_timestamp": datetime.now().isoformat(),
        "execution_time_ms": round((perf_counter() - started) * 1000, 2),
        "scan_failed": core_modules_failed,
        "scan_failure_reason": (
            f"Behavior engine: {behavior_result.get('error', 'failed')} | "
            f"HTTP scanner: {scanner_result.get('error', 'failed')}"
            if core_modules_failed else None
        ),
        "unified_assessment": unified,
        "security_behavior_engine": behavior_result,
        "combined_scanner": scanner_result,
        "robots_txt_analysis": robots_result,
        "user_discovery": user_discovery_result,
    }


def print_master_report(result: Dict[str, Any]) -> None:
    print("\n" + "#" * 70)
    print("#  MASTER SECURITY SCAN REPORT")
    print("#" * 70)
    print(f"Target             : {result['target']}")
    print(f"Scan Timestamp     : {result['scan_timestamp']}")
    print(f"Execution Time     : {result['execution_time_ms']} ms")

    ua = result["unified_assessment"]
    print(f"\nUNIFIED SCORE      : {ua['unified_score_percent']}%  ({ua['rating']})")
    comp = ua["components"]
    print(f"  - Behavior Engine Score : {comp['behavior_engine_score']}")
    print(f"  - Combined Scanner Score: {comp['combined_scanner_score']}")
    print(f"  - robots.txt Penalty   : -{comp['robots_high_risk_paths_penalty']} "
          f"({comp['robots_high_risk_paths_count']} high-risk path(s))")

    print("\n" + "-" * 70)
    print("1) SECURITY BEHAVIOR PROFILING ENGINE")
    print("-" * 70)
    be = result["security_behavior_engine"]
    if be.get("success"):
        overall = be["report"]["overall"]
        print(f"  Score: {overall['score']}/100 | Risk: {overall['risk_level']} "
              f"| Consistency: {overall['behavioral_consistency']}")
        print(f"  Anomalies: {overall['anomalies_count']} | "
              f"Correlated Risks: {overall['correlated_risks_count']}")
    else:
        print(f"  FAILED: {be.get('error')}")

    print("\n" + "-" * 70)
    print("2) COMBINED SCANNER (Headers / Cookies / Methods / Redirects)")
    print("-" * 70)
    cs = result["combined_scanner"]
    if cs.get("success"):
        print(f"  Score: {cs['overall_score_percent']}%")
        print(f"  Confirmed Security Findings: {len(cs['confirmed_security_findings'])}")
        for f in cs["confirmed_security_findings"]:
            print(f"    [CONFIRMED] {f['check']} ({f['severity']})")
    else:
        print(f"  FAILED: {cs.get('error')}")

    print("\n" + "-" * 70)
    print("3) ROBOTS.TXT ANALYSIS")
    print("-" * 70)
    rb = result["robots_txt_analysis"]
    if rb.get("success"):
        if rb.get("robots_found"):
            s = rb["summary"]
            print(f"  User-Agents: {s['user_agents_count']} | "
                  f"Disallowed: {s['disallowed_count']} | "
                  f"Interesting: {s['interesting_paths_count']}")
            for p in rb["interesting_paths"]:
                print(f"    [!] {p['path']} — {p['category']} ({p['severity']})")
        else:
            print(f"  robots.txt not usable: {rb.get('note')}")
    else:
        print(f"  FAILED: {rb.get('error')}")

    print("\n" + "-" * 70)
    print("4) DISCOVERED IDENTITIES (exposed by the target site itself)")
    print("-" * 70)
    ud = result["user_discovery"]
    if ud.get("success"):
        if ud["discovered_identities"]:
            for ident in ud["discovered_identities"]:
                platform = f" [{ident['platform']}]" if "platform" in ident else ""
                found_on = f" (found on {ident.get('found_on', '?')})"
                print(f"    [{ident['type']}]{platform}: {ident['value']}{found_on}")
            print(f"  Note: {ud['note']}")
        else:
            print("  None found.")
    else:
        print(f"  FAILED: {ud.get('error')}")

    print("\n" + "#" * 70 + "\n")


def create_master_blueprint():
    try:
        from flask import Blueprint, jsonify, request
    except ImportError:
        return None

    bp = Blueprint("master_security", __name__)

    @bp.route("/scan", methods=["POST"])
    def scan_endpoint():
        data = request.get_json() or {}
        target_url = data.get("url") or data.get("target")

        if not target_url:
            return jsonify({"error": "Missing required 'url' parameter"}), 400

        timeout = float(data.get("timeout", 10.0))

        try:
            result = run_master_scan(target_url, timeout=timeout)
            return jsonify(result), 200
        except Exception as e:
            return jsonify({"error": f"Master scan failed: {str(e)}"}), 500

    @bp.route("/health", methods=["GET"])
    def health():
        return jsonify({
            "module": "Master Security Toolkit (Behavior Engine + Combined Scanner + Robots Analyzer)",
            "status": "operational",
        }), 200

    return bp

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Master Link — يربط الثلاث أدوات ويعطي تقرير موحّد"
    )
    parser.add_argument("--url", help="Target URL")
    parser.add_argument("--output", help="Path to save the JSON report")
    args = parser.parse_args()

    if not args.url:
        args.url = input("Enter target URL: ").strip()

    result = run_master_scan(args.url)
    print_master_report(result)

    if args.output:
        directory = os.path.dirname(args.output)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False, default=str)
        print(f"[+] Saved: {args.output}")