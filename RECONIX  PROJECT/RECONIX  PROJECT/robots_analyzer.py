import requests
import json
import os
import argparse

from urllib.parse import urlparse
from datetime import datetime


# ========================================
# URL NORMALIZATION
# ========================================

def normalize_url(url):

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if not parsed.netloc:
        raise ValueError("Invalid URL")

    return f"{parsed.scheme}://{parsed.netloc}"


# ========================================
# GET ROBOTS.TXT
# ========================================

def get_robots(url):

    robots_url = url.rstrip("/") + "/robots.txt"

    try:

        response = requests.get(
            robots_url,
            timeout=10,
            headers={
                "User-Agent":
                "SecurityToolkit-RobotsAnalyzer/1.0"
            },
            allow_redirects=False
        )

        return response

    except requests.RequestException as error:

        print(f"[-] Request failed: {error}")

        return None


# ========================================
# ANALYZE ROBOTS.TXT
# ========================================

def analyze_robots(content):

    user_agents = []
    disallow = []
    allow = []
    sitemaps = []

    current_user_agent = None

    for line in content.splitlines():

        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        line = line.split("#")[0].strip()

        if ":" not in line:
            continue

        key, value = line.split(":", 1)

        key = key.strip().lower()
        value = value.strip()

        # USER-AGENT
        if key == "user-agent":

            current_user_agent = value

            if value not in user_agents:
                user_agents.append(value)

        # DISALLOW
        elif key == "disallow":

            if value:

                disallow.append({
                    "path": value,
                    "user_agent": current_user_agent
                })

        # ALLOW
        elif key == "allow":

            if value:

                allow.append({
                    "path": value,
                    "user_agent": current_user_agent
                })

        # SITEMAP
        elif key == "sitemap":

            if value and value not in sitemaps:

                sitemaps.append(value)

    return {
        "user_agents": user_agents,
        "disallow": disallow,
        "allow": allow,
        "sitemaps": sitemaps
    }


# ========================================
# DETECT INTERESTING PATHS
# ========================================

def detect_interesting_paths(disallow_paths):

    keywords = {

        "admin": {
            "category": "Admin Panel",
            "severity": "Medium"
        },

        "administrator": {
            "category": "Admin Panel",
            "severity": "Medium"
        },

        "backup": {
            "category": "Backup",
            "severity": "High"
        },

        "backups": {
            "category": "Backup",
            "severity": "High"
        },

        "api": {
            "category": "API",
            "severity": "Medium"
        },

        "private": {
            "category": "Private Area",
            "severity": "Medium"
        },

        "login": {
            "category": "Login",
            "severity": "Low"
        },

        "dashboard": {
            "category": "Dashboard",
            "severity": "Medium"
        },

        "config": {
            "category": "Configuration",
            "severity": "High"
        },

        "uploads": {
            "category": "Uploads",
            "severity": "Medium"
        },

        "upload": {
            "category": "Upload",
            "severity": "Medium"
        },

        "test": {
            "category": "Testing",
            "severity": "Low"
        },

        "dev": {
            "category": "Development",
            "severity": "Medium"
        },

        "debug": {
            "category": "Debug",
            "severity": "High"
        }
    }

    interesting = []
    seen_paths = set()

    for item in disallow_paths:

        path = item["path"]
        path_lower = path.lower()

        for keyword, info in keywords.items():

            if keyword in path_lower:

                if path not in seen_paths:

                    interesting.append({
                        "path": path,
                        "category": info["category"],
                        "severity": info["severity"],
                        "user_agent": item["user_agent"]
                    })

                    seen_paths.add(path)

                break

    return interesting


# ========================================
# DISPLAY RESULTS
# ========================================

def display_results(
    url,
    response,
    data,
    interesting_paths
):

    print("\n" + "=" * 60)

    print("             ROBOTS.TXT ANALYZER")

    print("=" * 60)

    print(f"\nTarget: {url}")
    print(f"Status: {response.status_code}")

    # USER AGENTS

    print("\n[User-Agents]")

    if data["user_agents"]:

        for agent in data["user_agents"]:

            print(f"  [+] {agent}")

    else:

        print("  None")

    # DISALLOWED PATHS

    print("\n[Disallowed Paths]")

    if data["disallow"]:

        for item in data["disallow"]:

            print(
                f"  [!] {item['path']} "
                f"(User-Agent: "
                f"{item['user_agent']})"
            )

    else:

        print("  None")

    # INTERESTING PATHS

    print("\n[Interesting Paths]")

    if interesting_paths:

        for item in interesting_paths:

            print(
                f"  [!] {item['path']}"
            )

            print(
                f"      Category: "
                f"{item['category']}"
            )

            print(
                f"      Severity: "
                f"{item['severity']}"
            )

    else:

        print("  None")

    # ALLOWED PATHS

    print("\n[Allowed Paths]")

    if data["allow"]:

        for item in data["allow"]:

            print(
                f"  [+] {item['path']} "
                f"(User-Agent: "
                f"{item['user_agent']})"
            )

    else:

        print("  None")

    # SITEMAPS

    print("\n[Sitemaps]")

    if data["sitemaps"]:

        for sitemap in data["sitemaps"]:

            print(f"  [+] {sitemap}")

    else:

        print("  None")

    # SUMMARY

    display_summary(
        data,
        interesting_paths
    )

    print("\n" + "=" * 60)


# ========================================
# SUMMARY
# ========================================

def display_summary(
    data,
    interesting_paths
):

    print("\n[Summary]")

    print(
        f"  User-Agents       : "
        f"{len(data['user_agents'])}"
    )

    print(
        f"  Disallowed Paths  : "
        f"{len(data['disallow'])}"
    )

    print(
        f"  Allowed Paths     : "
        f"{len(data['allow'])}"
    )

    print(
        f"  Sitemaps          : "
        f"{len(data['sitemaps'])}"
    )

    print(
        f"  Interesting Paths : "
        f"{len(interesting_paths)}"
    )

    categories = {}

    severities = {
        "Low": 0,
        "Medium": 0,
        "High": 0
    }

    for item in interesting_paths:

        category = item["category"]

        categories[category] = (
            categories.get(category, 0) + 1
        )

        severity = item["severity"]

        if severity in severities:

            severities[severity] += 1

    if categories:

        print("\n  Categories:")

        for category, count in categories.items():

            print(
                f"    - {category}: "
                f"{count}"
            )

    print("\n  Severity:")

    print(
        f"    - High   : "
        f"{severities['High']}"
    )

    print(
        f"    - Medium : "
        f"{severities['Medium']}"
    )

    print(
        f"    - Low    : "
        f"{severities['Low']}"
    )


# ========================================
# SAVE JSON REPORT
# ========================================

def save_json_report(
    url,
    response,
    data,
    interesting_paths,
    output_path
):

    directory = os.path.dirname(output_path)

    if directory:

        os.makedirs(
            directory,
            exist_ok=True
        )

    report = {

        "scan_info": {

            "target": url,

            "robots_url":
            url.rstrip("/") + "/robots.txt",

            "status_code":
            response.status_code,

            "scanned_at":
            datetime.now().isoformat()
        },

        "user_agents":
        data["user_agents"],

        "disallowed_paths":
        data["disallow"],

        "allowed_paths":
        data["allow"],

        "sitemaps":
        data["sitemaps"],

        "interesting_paths":
        interesting_paths
    }

    try:

        with open(
            output_path,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                report,
                file,
                indent=4,
                ensure_ascii=False
            )

        print(
            f"\n[+] JSON report saved: "
            f"{output_path}"
        )

    except OSError as error:

        print(
            f"\n[-] Failed to save "
            f"JSON report: {error}"
        )


# ========================================
# SAVE HTML REPORT
# ========================================

def save_html_report(
    url,
    response,
    data,
    interesting_paths,
    output_path
):

    directory = os.path.dirname(output_path)

    if directory:

        os.makedirs(
            directory,
            exist_ok=True
        )

    user_agents_count = len(
        data["user_agents"]
    )

    disallow_count = len(
        data["disallow"]
    )

    allow_count = len(
        data["allow"]
    )

    sitemap_count = len(
        data["sitemaps"]
    )

    interesting_count = len(
        interesting_paths
    )

    # ====================================
    # INTERESTING PATHS
    # ====================================

    interesting_html = ""

    if interesting_paths:

        for item in interesting_paths:

            severity_class = (
                item["severity"].lower()
            )

            interesting_html += f"""
            <tr>
                <td>{item["path"]}</td>

                <td>
                    {item["category"]}
                </td>

                <td>
                    <span class="severity {severity_class}">
                        {item["severity"]}
                    </span>
                </td>

                <td>
                    {item["user_agent"]}
                </td>
            </tr>
            """

    else:

        interesting_html = """
        <tr>
            <td colspan="4">
                No interesting paths detected
            </td>
        </tr>
        """

    # ====================================
    # USER AGENTS
    # ====================================

    agents_html = ""

    for agent in data["user_agents"]:

        agents_html += f"""
        <li>{agent}</li>
        """

    if not agents_html:

        agents_html = "<li>None</li>"

    # ====================================
    # SITEMAPS
    # ====================================

    sitemap_html = ""

    for sitemap in data["sitemaps"]:

        sitemap_html += f"""
        <li>
            <a
                href="{sitemap}"
                target="_blank"
            >
                {sitemap}
            </a>
        </li>
        """

    if not sitemap_html:

        sitemap_html = "<li>None</li>"

    # ====================================
    # HTML
    # ====================================

    html = f"""
<!DOCTYPE html>

<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width,
                 initial-scale=1.0"
    >

    <title>
        Robots.txt Security Report
    </title>

    <style>

        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            padding: 30px;

            font-family:
                Arial,
                Helvetica,
                sans-serif;

            background: #f4f6f8;

            color: #222;
        }}

        .container {{
            max-width: 1100px;

            margin: auto;
        }}

        header {{
            background: #111827;

            color: white;

            padding: 30px;

            border-radius: 12px;

            margin-bottom: 25px;
        }}

        header h1 {{
            margin: 0 0 10px;
        }}

        header p {{
            margin: 5px 0;

            color: #d1d5db;
        }}

        .stats {{
            display: grid;

            grid-template-columns:
                repeat(
                    auto-fit,
                    minmax(180px, 1fr)
                );

            gap: 15px;

            margin-bottom: 25px;
        }}

        .card {{
            background: white;

            padding: 20px;

            border-radius: 10px;

            box-shadow:
                0 3px 10px
                rgba(0, 0, 0, 0.08);
        }}

        .card h3 {{
            margin: 0;

            font-size: 14px;

            color: #6b7280;
        }}

        .card .number {{
            font-size: 30px;

            font-weight: bold;

            margin-top: 8px;
        }}

        section {{
            background: white;

            padding: 25px;

            border-radius: 12px;

            margin-bottom: 25px;

            box-shadow:
                0 3px 10px
                rgba(0, 0, 0, 0.06);
        }}

        section h2 {{
            margin-top: 0;
        }}

        table {{
            width: 100%;

            border-collapse: collapse;
        }}

        th,
        td {{
            text-align: left;

            padding: 12px;

            border-bottom:
                1px solid #e5e7eb;
        }}

        th {{
            background: #f9fafb;
        }}

        .severity {{
            padding: 5px 10px;

            border-radius: 20px;

            font-size: 12px;

            font-weight: bold;
        }}

        .high {{
            background: #fee2e2;

            color: #b91c1c;
        }}

        .medium {{
            background: #fef3c7;

            color: #92400e;
        }}

        .low {{
            background: #dcfce7;

            color: #166534;
        }}

        ul {{
            padding-left: 20px;
        }}

        li {{
            margin-bottom: 8px;
        }}

        a {{
            color: #2563eb;

            text-decoration: none;
        }}

        a:hover {{
            text-decoration: underline;
        }}

        footer {{
            text-align: center;

            color: #6b7280;

            margin-top: 30px;
        }}

        @media (max-width: 700px) {{

            body {{
                padding: 15px;
            }}

            table {{
                font-size: 13px;
            }}

            th,
            td {{
                padding: 8px;
            }}

        }}

    </style>

</head>


<body>

<div class="container">


    <header>

        <h1>
            Robots.txt Security Report
        </h1>

        <p>
            <strong>Target:</strong>
            {url}
        </p>

        <p>
            <strong>Status:</strong>
            {response.status_code}
        </p>

        <p>
            <strong>Scanned:</strong>
            {datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )}
        </p>

    </header>


    <!-- STATISTICS -->

    <div class="stats">


        <div class="card">

            <h3>
                User Agents
            </h3>

            <div class="number">
                {user_agents_count}
            </div>

        </div>


        <div class="card">

            <h3>
                Disallowed Paths
            </h3>

            <div class="number">
                {disallow_count}
            </div>

        </div>


        <div class="card">

            <h3>
                Allowed Paths
            </h3>

            <div class="number">
                {allow_count}
            </div>

        </div>


        <div class="card">

            <h3>
                Sitemaps
            </h3>

            <div class="number">
                {sitemap_count}
            </div>

        </div>


        <div class="card">

            <h3>
                Interesting Paths
            </h3>

            <div class="number">
                {interesting_count}
            </div>

        </div>


    </div>


    <!-- INTERESTING PATHS -->

    <section>

        <h2>
            Interesting Paths
        </h2>

        <table>

            <thead>

                <tr>

                    <th>
                        Path
                    </th>

                    <th>
                        Category
                    </th>

                    <th>
                        Severity
                    </th>

                    <th>
                        User-Agent
                    </th>

                </tr>

            </thead>

            <tbody>

                {interesting_html}

            </tbody>

        </table>

    </section>


    <!-- USER AGENTS -->

    <section>

        <h2>
            User-Agents
        </h2>

        <ul>

            {agents_html}

        </ul>

    </section>


    <!-- SITEMAPS -->

    <section>

        <h2>
            Sitemaps
        </h2>

        <ul>

            {sitemap_html}

        </ul>

    </section>


    <footer>

        Security Toolkit
        -
        Robots.txt Analyzer

    </footer>


</div>

</body>

</html>
"""

    try:

        with open(
            output_path,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(html)

        print(
            f"[+] HTML report saved: "
            f"{output_path}"
        )

    except OSError as error:

        print(
            f"[-] Failed to save "
            f"HTML report: {error}"
        )


# ========================================
# HANDLE HTTP STATUS
# ========================================

def handle_status_code(response):

    status = response.status_code

    if status == 200:

        print(
            "[+] robots.txt found!"
        )

        return True

    elif status == 403:

        print(
            "[!] robots.txt access "
            "forbidden (HTTP 403)"
        )

    elif status == 404:

        print(
            "[-] robots.txt not found "
            "(HTTP 404)"
        )

    elif 300 <= status < 400:

        location = response.headers.get(
            "Location",
            "Unknown"
        )

        print(
            f"[>] Redirect detected "
            f"(HTTP {status})"
        )

        print(
            f"[>] Location: {location}"
        )

    elif 500 <= status < 600:

        print(
            f"[!] Server error "
            f"(HTTP {status})"
        )

    else:

        print(
            f"[?] Unexpected HTTP "
            f"status: {status}"
        )

    return False


# ========================================
# MAIN
# ========================================

def main():

    parser = argparse.ArgumentParser(
        description=
        "Security Toolkit - "
        "Robots.txt Analyzer"
    )

    parser.add_argument(
        "--url",
        help="Target URL"
    )

    parser.add_argument(
        "--output",
        default="reports/robots_report.json",
        help=
        "JSON report output path "
        "(default: "
        "reports/robots_report.json)"
    )

    args = parser.parse_args()


    print("""
========================================
       SECURITY TOOLKIT
       Robots.txt Analyzer
========================================
""")


    # TARGET URL

    if args.url:

        target = args.url

    else:

        target = input(
            "Enter Target URL: "
        )


    # NORMALIZE URL

    try:

        target = normalize_url(
            target
        )

    except ValueError:

        print(
            "[-] Invalid URL"
        )

        return


    # REQUEST

    print(
        "\n[+] Checking robots.txt..."
    )

    response = get_robots(
        target
    )

    if response is None:

        return


    # STATUS

    if not handle_status_code(
        response
    ):

        return


    # ANALYZE

    data = analyze_robots(
        response.text
    )


    # INTERESTING PATHS

    interesting_paths = (
        detect_interesting_paths(
            data["disallow"]
        )
    )


    # DISPLAY

    display_results(
        target,
        response,
        data,
        interesting_paths
    )


    # JSON REPORT

    save_json_report(
        target,
        response,
        data,
        interesting_paths,
        args.output
    )


    # HTML REPORT

    html_output = (
        os.path.splitext(
            args.output
        )[0]
        + ".html"
    )

    save_html_report(
        target,
        response,
        data,
        interesting_paths,
        html_output
    )


# ========================================
# ENTRY POINT
# ========================================

if __name__ == "__main__":

    main()