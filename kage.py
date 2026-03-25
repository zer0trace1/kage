from __future__ import annotations

import ipaddress
import os
from typing import Any, Optional

import requests
import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from dotenv import load_dotenv
load_dotenv()

app = typer.Typer(
    help="KAGE - IOC enrichment CLI",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()
VERSION = "0.1.0"

IP_API_URL = "http://ip-api.com/json/{query}"
IP_API_FIELDS = ",".join(
    [
        "status",
        "message",
        "country",
        "countryCode",
        "regionName",
        "city",
        "timezone",
        "isp",
        "org",
        "as",
        "asname",
        "proxy",
        "hosting",
        "mobile",
        "query",
    ]
)

ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"


def validate_ip(value: str) -> ipaddress._BaseAddress:
    try:
        return ipaddress.ip_address(value)
    except ValueError as exc:
        raise typer.BadParameter(f"'{value}' no es una IP válida.") from exc


def classify_ip(
    parsed_ip: ipaddress._BaseAddress,
    geo_data: dict[str, Any],
    abuse_data: Optional[dict[str, Any]],
) -> tuple[str, str]:
    if parsed_ip.is_private:
        return "private", "IP privada"
    if parsed_ip.is_loopback:
        return "local", "Loopback"
    if parsed_ip.is_multicast:
        return "special", "Multicast"
    if parsed_ip.is_reserved:
        return "special", "Reservada"

    if abuse_data:
        score = abuse_data.get("abuseConfidenceScore", 0) or 0
        reports = abuse_data.get("totalReports", 0) or 0
        is_tor = abuse_data.get("isTor", False)
        is_whitelisted = abuse_data.get("isWhitelisted", False)
        usage_type = (abuse_data.get("usageType") or "").lower()
        isp = (abuse_data.get("isp") or "").lower()

        known_public_infra = (
            is_whitelisted
            or "content delivery" in usage_type
            or "cdn" in usage_type
            or any(x in isp for x in ["google", "cloudflare", "amazon", "aws", "microsoft", "azure", "akamai", "fastly"])
        )

        if is_tor or score >= 80:
            return "malicious", "Malicious"

        if known_public_infra:
            if score >= 50:
                return "suspicious", "Suspicious"
            return "clean", "Known public infrastructure"

        if score >= 25:
            return "suspicious", "Suspicious"

        if reports >= 5:
            return "suspicious", "Suspicious"

        return "clean", "Clean"

    if geo_data.get("proxy") and not geo_data.get("hosting"):
        return "suspicious", "Suspicious"

    return "unknown", "Unknown"


def fetch_ip_api(ip: str) -> tuple[dict[str, Any], dict[str, str]]:
    response = requests.get(
        IP_API_URL.format(query=ip),
        params={"fields": IP_API_FIELDS},
        timeout=10,
    )
    response.raise_for_status()
    return response.json(), response.headers


def fetch_abuseipdb(ip: str, max_age_days: int = 90) -> Optional[dict[str, Any]]:
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return None

    headers = {
        "Accept": "application/json",
        "Key": api_key,
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": str(max_age_days),
    }

    response = requests.get(
        ABUSEIPDB_CHECK_URL,
        headers=headers,
        params=params,
        timeout=10,
    )
    response.raise_for_status()
    payload = response.json()
    return payload.get("data")


def make_overview_table(
    ip: str,
    verdict_label: str,
    verdict_reason: str,
) -> Table:
    table = Table(
        title="KAGE Verdict",
        box=box.ROUNDED,
        show_lines=False,
    )
    table.add_column("Campo", style="cyan", no_wrap=True)
    table.add_column("Valor", style="white")
    table.add_row("IOC", ip)
    table.add_row("Tipo", "IPv4/IPv6")
    table.add_row("Clasificación", verdict_label)
    table.add_row("Motivo", verdict_reason)
    return table


def make_geo_table(geo_data: dict[str, Any], headers: dict[str, str]) -> Table:
    table = Table(
        title="Geolocation / Network Context",
        box=box.ROUNDED,
        show_lines=False,
    )
    table.add_column("Campo", style="cyan", no_wrap=True)
    table.add_column("Valor", style="white")

    table.add_row("IP", str(geo_data.get("query", "-")))
    table.add_row("País", f"{geo_data.get('country', '-')} ({geo_data.get('countryCode', '-')})")
    table.add_row("Región", str(geo_data.get("regionName", "-")))
    table.add_row("Ciudad", str(geo_data.get("city", "-")))
    table.add_row("Timezone", str(geo_data.get("timezone", "-")))
    table.add_row("ISP", str(geo_data.get("isp", "-")))
    table.add_row("Org", str(geo_data.get("org", "-")))
    table.add_row("AS", str(geo_data.get("as", "-")))
    table.add_row("AS Name", str(geo_data.get("asname", "-")))
    table.add_row("Proxy", str(bool(geo_data.get("proxy", False))))
    table.add_row("Hosting", str(bool(geo_data.get("hosting", False))))
    table.add_row("Mobile", str(bool(geo_data.get("mobile", False))))

    rate_remaining = headers.get("X-Rl")
    rate_reset = headers.get("X-Ttl")
    if rate_remaining is not None:
        table.add_row("ip-api rate remaining", rate_remaining)
    if rate_reset is not None:
        table.add_row("ip-api rate reset (s)", rate_reset)

    return table


def make_abuse_table(abuse_data: dict[str, Any]) -> Table:
    table = Table(
        title="Reputation / Abuse Signals",
        box=box.ROUNDED,
        show_lines=False,
    )
    table.add_column("Campo", style="cyan", no_wrap=True)
    table.add_column("Valor", style="white")

    table.add_row("Public", str(abuse_data.get("isPublic", "-")))
    table.add_row("Whitelisted", str(abuse_data.get("isWhitelisted", "-")))
    table.add_row("Abuse score", str(abuse_data.get("abuseConfidenceScore", "-")))
    table.add_row("Total reports", str(abuse_data.get("totalReports", "-")))
    table.add_row("Distinct users", str(abuse_data.get("numDistinctUsers", "-")))
    table.add_row("Usage type", str(abuse_data.get("usageType", "-")))
    table.add_row("ISP", str(abuse_data.get("isp", "-")))
    table.add_row("Domain", str(abuse_data.get("domain", "-")))
    table.add_row("Tor", str(abuse_data.get("isTor", "-")))
    table.add_row("Last reported", str(abuse_data.get("lastReportedAt", "-")))

    return table


@app.command()
def version() -> None:
    """Muestra la versión de KAGE."""
    console.print(f"[bold cyan]KAGE[/bold cyan] v{VERSION}")


@app.command()
def ip(
    value: str = typer.Argument(..., help="Dirección IP a enriquecer."),
    max_age_days: int = typer.Option(
        90,
        "--max-age-days",
        min=1,
        max=365,
        help="Ventana de días para AbuseIPDB.",
    ),
) -> None:
    """Enriquece una IP con contexto geográfico, ASN y reputación opcional."""
    parsed_ip = validate_ip(value)

    console.print(
        Panel.fit(
            f"[bold white]KAGE[/bold white] → analizando [cyan]{parsed_ip}[/cyan]",
            border_style="cyan",
        )
    )

    if parsed_ip.is_private or parsed_ip.is_loopback:
        console.print(
            "[yellow]Aviso:[/yellow] la IP es privada/local. "
            "La reputación externa normalmente no tendrá sentido."
        )

    try:
        geo_data, geo_headers = fetch_ip_api(str(parsed_ip))
    except requests.RequestException as exc:
        console.print(f"[red]Error consultando ip-api:[/red] {exc}")
        raise typer.Exit(code=1)

    if geo_data.get("status") != "success":
        console.print(
            f"[red]ip-api devolvió un error:[/red] {geo_data.get('message', 'desconocido')}"
        )
        raise typer.Exit(code=1)

    abuse_data: Optional[dict[str, Any]] = None
    abuse_enabled = bool(os.getenv("ABUSEIPDB_API_KEY"))

    if abuse_enabled:
        try:
            abuse_data = fetch_abuseipdb(str(parsed_ip), max_age_days=max_age_days)
        except requests.RequestException as exc:
            console.print(f"[yellow]AbuseIPDB no disponible:[/yellow] {exc}")
    else:
        console.print(
            "[dim]ABUSEIPDB_API_KEY no definida: se omite reputación avanzada.[/dim]"
        )

    verdict_key, verdict_label = classify_ip(parsed_ip, geo_data, abuse_data)

    reason_map = {
        "private": "Dirección privada",
        "local": "Dirección local/loopback",
        "special": "Rango especial o reservado",
        "malicious": "Score alto o señales fuertes de abuso",
        "suspicious": "Se observaron señales relevantes de riesgo",
        "clean": "Sin señales relevantes o infraestructura pública conocida",
        "unknown": "Sin suficiente contexto reputacional",
    }
    verdict_reason = reason_map.get(verdict_key, "Clasificación no determinada")

    console.print()
    console.print(make_overview_table(str(parsed_ip), verdict_label, verdict_reason))
    console.print()
    console.print(make_geo_table(geo_data, geo_headers))

    if abuse_data:
        console.print()
        console.print(make_abuse_table(abuse_data))


if __name__ == "__main__":
    app()