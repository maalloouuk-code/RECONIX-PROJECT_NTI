import json
import logging
import asyncio
import ipaddress
import sys

import typer
import httpx
import dns.resolver
import dns.reversename
import phonenumbers
from phonenumbers import geocoder, carrier
from email_validator import validate_email, EmailNotValidError

from rich.console import Console
from rich.panel import Panel
from rich.logging import RichHandler
from rich.prompt import IntPrompt, Prompt

console = Console()

# ---------------------------------------------------------------------------
# Output helpers (from core/output.py)
# ---------------------------------------------------------------------------

def format_output(data, format_type: str = "table"):
    if format_type == "json":
        if hasattr(data, "model_dump"):
            print(json.dumps(data.model_dump(), indent=2))
        else:
            print(json.dumps(data, indent=2, default=str))
    elif format_type == "jsonl":
        if isinstance(data, list):
            for item in data:
                print(json.dumps(item, default=str))
        else:
            print(json.dumps(data, default=str))
    else:
        console.print(data)


# ---------------------------------------------------------------------------
# Logger (from utils/logger.py)
# ---------------------------------------------------------------------------

def setup_logger(debug: bool = False):
    level = logging.DEBUG if debug else logging.INFO

    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, show_path=debug, markup=True)],
    )

    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    return logging.getLogger("osint")


logger = logging.getLogger("osint")

# ---------------------------------------------------------------------------
# Username Intelligence (Sherlock style) - from cli/username.py
# ---------------------------------------------------------------------------

username_app = typer.Typer(help="Username Intelligence (Sherlock style)")

SITES = {
    "GitHub": {"url": "https://github.com/{}", "error_type": "status_code"},
    "Reddit": {"url": "https://www.reddit.com/user/{}", "error_type": "status_code"},
    "HackerNews": {"url": "https://news.ycombinator.com/user?id={}", "error_type": "message", "error_msg": "No such user."},
    "Linktree": {"url": "https://linktr.ee/{}", "error_type": "status_code"},
    "Patreon": {"url": "https://www.patreon.com/{}", "error_type": "status_code"},
    "Vimeo": {"url": "https://vimeo.com/{}", "error_type": "status_code"},
    "Flickr": {"url": "https://www.flickr.com/people/{}/", "error_type": "status_code"},
    "Instagram": {"url": "https://www.instagram.com/{}/", "error_type": "status_code"},
    "Facebook": {"url": "https://www.facebook.com/{}", "error_type": "status_code"},
    "X (Twitter)": {"url": "https://twitter.com/{}", "error_type": "status_code"},
    "Pinterest": {"url": "https://www.pinterest.com/{}/", "error_type": "status_code"},
    "LinkedIn": {"url": "https://www.linkedin.com/in/{}/", "error_type": "status_code"},
    "TikTok": {"url": "https://www.tiktok.com/@{}", "error_type": "status_code"},
    "YouTube": {"url": "https://www.youtube.com/@{}", "error_type": "status_code"},
    "Twitch": {"url": "https://www.twitch.tv/{}", "error_type": "status_code"},
    "Medium": {"url": "https://medium.com/@{}", "error_type": "status_code"},
    "Spotify": {"url": "https://open.spotify.com/user/{}", "error_type": "status_code"},
    "SoundCloud": {"url": "https://soundcloud.com/{}", "error_type": "status_code"},
    "Telegram": {"url": "https://t.me/{}", "error_type": "status_code"},
    "Snapchat": {"url": "https://www.snapchat.com/add/{}", "error_type": "status_code"},
    "Tumblr": {"url": "https://{}.tumblr.com", "error_type": "status_code"},
    "WordPress": {"url": "https://{}.wordpress.com", "error_type": "status_code"},
    "Blogger": {"url": "https://{}.blogspot.com", "error_type": "status_code"},
    "GitLab": {"url": "https://gitlab.com/{}", "error_type": "status_code"},
    "BitBucket": {"url": "https://bitbucket.org/{}/", "error_type": "status_code"},
    "About.me": {"url": "https://about.me/{}", "error_type": "status_code"},
    "Wattpad": {"url": "https://www.wattpad.com/user/{}", "error_type": "status_code"},
    "Canva": {"url": "https://www.canva.com/{}", "error_type": "status_code"},
    "Behance": {"url": "https://www.behance.net/{}", "error_type": "status_code"},
    "Dribbble": {"url": "https://dribbble.com/{}", "error_type": "status_code"},
}


async def check_site(client: httpx.AsyncClient, site_name: str, site_data: dict, username: str):
    url = site_data["url"].format(username)
    try:
        response = await client.get(url, timeout=10.0, follow_redirects=True)

        if response.status_code in (401, 403, 406, 429, 503):
            return site_name, url, "BLOCKED"

        if site_data["error_type"] == "status_code":
            if response.status_code == 200:
                return site_name, url, "FOUND"
            else:
                return site_name, url, "NOT_FOUND"
        elif site_data["error_type"] == "message":
            if site_data["error_msg"] in response.text:
                return site_name, url, "NOT_FOUND"
            else:
                return site_name, url, "FOUND"

    except httpx.RequestError:
        return site_name, url, "NOT_FOUND"
    except Exception:
        return site_name, url, "NOT_FOUND"


async def run_sherlock(username: str, timeout: int):
    console.print(f"\n[*] Checking username [bold cyan]{username}[/bold cyan] on:")

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    }

    async with httpx.AsyncClient(headers=headers) as client:
        tasks = [
            check_site(client, site_name, site_data, username)
            for site_name, site_data in SITES.items()
        ]

        for coro in asyncio.as_completed(tasks):
            site_name, url, status = await coro
            if status == "FOUND":
                console.print(f"[bold green][+][/bold green] {site_name}: {url}")
            elif status == "BLOCKED":
                console.print(f"[bold yellow][!][/bold yellow] {site_name}: Blocked / Rate Limited")
            else:
                console.print(f"[bold red][-][/bold red] {site_name}: Not Found!")

    console.print("\n[bold green][+] Search complete![/bold green]")


@username_app.command("search")
def search_username(
    username: str = typer.Argument(..., help="Username to investigate"),
    timeout: int = typer.Option(10, help="Timeout in seconds"),
):
    """Search for a username across social networks (Sherlock style)"""
    asyncio.run(run_sherlock(username, timeout))


# ---------------------------------------------------------------------------
# Email Intelligence - from cli/email.py
# ---------------------------------------------------------------------------

email_app = typer.Typer(help="Email Intelligence")


async def get_dns_records(domain: str, record_type: str):
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(a) for a in answers]
    except Exception:
        return []


@email_app.command("analyze")
def analyze_email(
    email: str = typer.Argument(..., help="Email address to analyze"),
    output: str = typer.Option("table", "--output", "-o", help="Output format"),
):
    """Analyze an email address."""
    is_valid = False
    normalized = email
    domain = ""
    try:
        valid = validate_email(email, check_deliverability=False)
        normalized = valid.normalized
        domain = valid.domain
        is_valid = True
    except EmailNotValidError as e:
        console.print(f"[bold red]Validation error: {e}[/bold red]")
        if "@" in email:
            domain = email.split("@")[-1]

    if not domain:
        raise typer.Exit(1)

    async def collect():
        mx, spf, dmarc = await asyncio.gather(
            get_dns_records(domain, "MX"),
            get_dns_records(domain, "TXT"),
            get_dns_records(f"_dmarc.{domain}", "TXT"),
        )
        return mx, spf, dmarc

    mx_records, txt_records, dmarc_records = asyncio.run(collect())

    spf_found = "NO"
    for txt in txt_records:
        if "v=spf1" in txt.lower():
            spf_found = "YES"
            break

    dmarc_found = "NO"
    for txt in dmarc_records:
        if "v=dmarc1" in txt.lower():
            dmarc_found = "YES"
            break

    result = {
        "email": email,
        "valid": "YES" if is_valid else "NO",
        "normalized": normalized,
        "domain": domain,
        "disposable": "UNKNOWN",
        "mx_present": "YES" if mx_records else "NO",
        "spf_present": spf_found,
        "dmarc_present": dmarc_found,
    }

    if output == "json":
        format_output(result, "json")
        return

    panel_text = f"""[bold]Email:[/bold]        {result['email']}
[bold]Valid Syntax:[/bold] {result['valid']}
[bold]Normalized:[/bold]   {result['normalized']}
[bold]Domain:[/bold]       {result['domain']}

[bold]Security:[/bold]
MX Records:   {result['mx_present']}
SPF:          {result['spf_present']}
DMARC:        {result['dmarc_present']}"""

    console.print(Panel(panel_text, title="Email Intelligence", border_style="cyan"))


# ---------------------------------------------------------------------------
# IP Intelligence - from cli/ip.py
# ---------------------------------------------------------------------------

ip_app = typer.Typer(help="IP Address Intelligence")


def is_valid_ip(ip_str: str) -> bool:
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


async def get_rdap(ip_str: str):
    url = f"https://rdap.arin.net/registry/ip/{ip_str}"
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, timeout=5.0)
            if resp.status_code == 200:
                data = resp.json()
                name = data.get("name", "Unknown")
                return {"asn": "Unknown", "organization": name}
    except Exception:
        pass
    return {"asn": "Unknown", "organization": "Unknown"}


async def get_reverse_dns(ip_str: str):
    try:
        addr = dns.reversename.from_address(ip_str)
        answers = dns.resolver.resolve(addr, "PTR")
        return str(answers[0])
    except Exception:
        return "Unknown"


@ip_app.command("analyze")
def analyze_ip(
    ip: str = typer.Argument(..., help="IP address to analyze"),
    output: str = typer.Option("table", "--output", "-o", help="Output format (table, json, csv)"),
):
    """Perform a comprehensive passive IP investigation."""
    if not is_valid_ip(ip):
        console.print(f"[bold red]Error: Invalid IP address: {ip}[/bold red]")
        raise typer.Exit(1)

    addr = ipaddress.ip_address(ip)

    async def collect():
        rdap, rdns = await asyncio.gather(
            get_rdap(ip),
            get_reverse_dns(ip),
        )
        return rdap, rdns

    rdap, rdns = asyncio.run(collect())

    result = {
        "ip": ip,
        "version": f"IPv{addr.version}",
        "public": "YES" if not addr.is_private else "NO",
        "reverse_dns": rdns,
        "asn": rdap.get("asn"),
        "organization": rdap.get("organization"),
    }

    if output == "json":
        format_output(result, "json")
        return

    panel_text = f"""[bold]IP:[/bold]             {result['ip']}
[bold]Version:[/bold]        {result['version']}
[bold]Public:[/bold]         {result['public']}
[bold]Reverse DNS:[/bold]    {result['reverse_dns']}
[bold]ASN:[/bold]            {result['asn']}
[bold]Organization:[/bold]   {result['organization']}"""

    console.print(Panel(panel_text, title="IP Intelligence", border_style="cyan"))


@ip_app.command("dns")
def ip_dns(ip: str = typer.Argument(...)):
    """Reverse DNS lookup for IP."""
    if not is_valid_ip(ip):
        console.print("[bold red]Invalid IP[/bold red]")
        raise typer.Exit(1)

    async def run():
        rdns = await get_reverse_dns(ip)
        console.print(f"[bold]Reverse DNS for {ip}:[/bold] {rdns}")

    asyncio.run(run())


# ---------------------------------------------------------------------------
# Phone Intelligence - from cli/phone.py
# ---------------------------------------------------------------------------

phone_app = typer.Typer(help="Phone Number Intelligence")


@phone_app.command("analyze")
def analyze_phone(
    phone: str = typer.Argument(..., help="Phone number to analyze"),
    country: str = typer.Option(None, "--country", "-c", help="ISO country code (e.g. EG, US) if number is local"),
    output: str = typer.Option("table", "--output", "-o", help="Output format"),
):
    """Analyze a phone number."""
    try:
        parsed = phonenumbers.parse(phone, country)
    except phonenumbers.phonenumberutil.NumberParseException as e:
        console.print(f"[bold red]Error parsing number: {e}[/bold red]")
        raise typer.Exit(1)

    is_valid = phonenumbers.is_valid_number(parsed)
    is_possible = phonenumbers.is_possible_number(parsed)

    formatted = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    country_name = geocoder.description_for_number(parsed, "en") or "Unknown"
    carrier_name = carrier.name_for_number(parsed, "en") or "Unknown"

    number_type = phonenumbers.number_type(parsed)
    type_str = "UNKNOWN"
    if number_type == phonenumbers.PhoneNumberType.MOBILE:
        type_str = "MOBILE"
    elif number_type == phonenumbers.PhoneNumberType.FIXED_LINE:
        type_str = "FIXED_LINE"
    elif number_type == phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE:
        type_str = "FIXED_LINE_OR_MOBILE"

    result = {
        "input": phone,
        "normalized": formatted,
        "country": country_name,
        "calling_code": f"+{parsed.country_code}",
        "valid": "YES" if is_valid else "NO",
        "possible": "YES" if is_possible else "NO",
        "type": type_str,
        "carrier": carrier_name,
    }

    if output == "json":
        format_output(result, "json")
        return

    panel_text = f"""[bold]Input:[/bold]          {result['input']}
[bold]Normalized:[/bold]     {result['normalized']}
[bold]Country:[/bold]        {result['country']}
[bold]Calling Code:[/bold]   {result['calling_code']}
[bold]Valid:[/bold]          {result['valid']}
[bold]Possible:[/bold]       {result['possible']}
[bold]Type:[/bold]           {result['type']}
[bold]Carrier:[/bold]        {result['carrier']}"""

    console.print(Panel(panel_text, title="Phone Intelligence", border_style="cyan"))


# ---------------------------------------------------------------------------
# Main app - from cli/main.py (بدون موديول investigate اللي بيعتمد على DB)
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="osint",
    help="Professional OSINT Framework",
    no_args_is_help=False,
    add_completion=False,
)

app.add_typer(username_app, name="username")
app.add_typer(ip_app, name="ip")
app.add_typer(phone_app, name="phone")
app.add_typer(email_app, name="email")


def interactive_menu():
    while True:
        console.print("\n[bold cyan]Main Menu[/bold cyan]")
        console.print("1) Username Search")
        console.print("2) Email Search")
        console.print("3) Domain Search (Coming Soon)")
        console.print("4) IP Address Search")
        console.print("5) Phone Number Search")
        console.print("0) Exit")

        choice = IntPrompt.ask("Select an option", choices=["0", "1", "2", "3", "4", "5"])

        try:
            if choice == 0:
                console.print("[bold red]Exiting...[/bold red]")
                raise typer.Exit()
            elif choice == 1:
                target = Prompt.ask("Enter username to search")
                if target:
                    search_username(username=target, timeout=10)
            elif choice == 2:
                target = Prompt.ask("Enter email to analyze")
                if target:
                    analyze_email(email=target, output="table")
            elif choice == 4:
                target = Prompt.ask("Enter IP to analyze")
                if target:
                    analyze_ip(ip=target, output="table")
            elif choice == 5:
                target = Prompt.ask("Enter Phone Number to analyze")
                if target:
                    analyze_phone(phone=target, country=None, output="table")
            elif choice in [3]:
                console.print("[yellow]This module is not yet implemented.[/yellow]")
        except typer.Exit:
            if choice == 0:
                raise
            # otherwise just catch and continue loop


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose/debug output"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress output"),
):
    """
    OSINT Framework - A professional intelligence gathering tool.
    """
    if not quiet:
        setup_logger(debug=verbose)
    else:
        logging.getLogger().setLevel(logging.CRITICAL)

    if not ctx.invoked_subcommand:
        if not quiet:
            print_banner()
        interactive_menu()


def print_banner():
    banner_text = """[bold green]
  ____  _____ _____ _   _ _____ 
 / __ \\|  ___|_   _| \\ | |_   _|
| |  | | |___  | | |  \\| | | |  
| |  | |\\___ \\ | | | . ` | | |  
| |__| |___) |_| |_| |\\  | | |  
 \\____/|____/|_____|_| \\_| |_|  
[/bold green]
[dim]Professional OSINT Framework v1.0.0 (single-file, no database)[/dim]
"""
    console.print(banner_text)
    console.print("[cyan][+] Providers: Configured   [+] Plugins: Loaded[/cyan]")


@app.command()
def version():
    """Print framework version"""
    print_banner()


if __name__ == "__main__":
    app()