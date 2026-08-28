#!/usr/bin/env python3
"""disclose-cli — build responsible disclosure reports."""

from __future__ import annotations

import json
from pathlib import Path

import click
import yaml
from rich.console import Console
from rich.panel import Panel

from . import __version__
from .cvss import suggest_severity
from .redact import redact_text
from .render import build_context, render_markdown, render_pdf

console = Console()

EXAMPLE_FINDING = {
    "title": "IDOR on order API allows cross-user data access",
    "researcher": "Sushant Bhardwaj",
    "email": "researcher@example.com",
    "asset": "api.example.com",
    "endpoint": "GET /api/orders/{id}",
    "vuln_type": "Insecure Direct Object Reference (IDOR)",
    "cwe": "CWE-639",
    "summary": (
        "Authenticated users can access other users' orders by changing the "
        "numeric order ID. No server-side ownership check is enforced."
    ),
    "steps": [
        "Log in as User A and note order ID 1001 owned by A.",
        "Log in as User B and obtain a valid session.",
        "As User B, request GET /api/orders/1001.",
        "Observe User A's order details including PII fields are returned.",
    ],
    "request": "GET /api/orders/1001 HTTP/1.1\nHost: api.example.com\nAuthorization: Bearer [REDACTED]",
    "response": "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"id\":1001,\"owner\":\"UserA\",\"email\":\"[REDACTED]\",...}",
    "impact": (
        "Any authenticated user can read arbitrary orders, exposing PII and "
        "purchase history at scale via ID enumeration."
    ),
    "remediation": (
        "Enforce object-level authorization: allow access only when "
        "order.owner_id == auth.user_id (or equivalent RBAC). Add tests for horizontal access."
    ),
    "program": "VDP / Bug Bounty",
    "unauthenticated": False,
    "exposes_pii": True,
    "exposes_financial": True,
    "privilege_escalation": True,
    "easy_exploit": True,
    "widespread": True,
}


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="disclose-cli")
def main() -> None:
    """Responsible disclosure report factory (Markdown + PDF)."""


@main.command("init")
@click.option(
    "-o",
    "--output",
    default="finding.yaml",
    show_default=True,
    type=click.Path(),
    help="Path for new finding YAML",
)
@click.option(
    "--type",
    "vuln_type",
    type=click.Choice(["idor", "misconfig", "info_disclosure", "generic"]),
    default="idor",
    show_default=True,
)
def init_cmd(output: str, vuln_type: str) -> None:
    """Write a starter finding YAML."""
    data = dict(EXAMPLE_FINDING)
    if vuln_type == "misconfig":
        data["title"] = "Security misconfiguration exposes sensitive directory listing"
        data["vuln_type"] = "Security Misconfiguration"
        data["cwe"] = "CWE-16 / CWE-548"
    elif vuln_type == "info_disclosure":
        data["title"] = "Unauthenticated information disclosure"
        data["vuln_type"] = "Information Disclosure"
        data["cwe"] = "CWE-200"
    path = Path(output)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    console.print(f"Wrote [cyan]{path}[/cyan] — edit, then run: disclose-cli build {path}")


@main.command("severity")
@click.option("--unauthenticated", is_flag=True)
@click.option("--exposes-pii", is_flag=True)
@click.option("--exposes-financial", is_flag=True)
@click.option("--privilege-escalation", is_flag=True)
@click.option("--rce", is_flag=True)
@click.option("--easy/--not-easy", default=True)
@click.option("--widespread", is_flag=True)
def severity_cmd(
    unauthenticated: bool,
    exposes_pii: bool,
    exposes_financial: bool,
    privilege_escalation: bool,
    rce: bool,
    easy: bool,
    widespread: bool,
) -> None:
    """Suggest qualitative severity from impact flags."""
    res = suggest_severity(
        unauthenticated=unauthenticated,
        exposes_pii=exposes_pii,
        exposes_financial=exposes_financial,
        privilege_escalation=privilege_escalation,
        rce=rce,
        easy_exploit=easy,
        widespread=widespread,
    )
    console.print(
        Panel(
            f"[bold]{res.rating}[/bold] (hint score {res.score_hint}/10)\n"
            + "\n".join(f"• {r}" for r in res.rationale),
            title="Severity helper",
        )
    )


@main.command("redact")
@click.argument("input_file", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), default=None)
def redact_cmd(input_file: str, output: str | None) -> None:
    """Redact common PII/secrets from a text file."""
    raw = Path(input_file).read_text(encoding="utf-8", errors="replace")
    cleaned, fired = redact_text(raw)
    out = Path(output) if output else Path(input_file).with_suffix(".redacted.txt")
    out.write_text(cleaned, encoding="utf-8")
    console.print(f"Wrote [cyan]{out}[/cyan]")
    console.print("Rules fired: " + (", ".join(fired) if fired else "none"))


@main.command("build")
@click.argument("finding", type=click.Path(exists=True))
@click.option(
    "--style",
    type=click.Choice(["hackerone", "certin", "vdp"]),
    default="hackerone",
    show_default=True,
)
@click.option("--md/--no-md", default=True, show_default=True)
@click.option("--pdf/--no-pdf", default=True, show_default=True)
@click.option(
    "-o",
    "--outdir",
    default="out",
    show_default=True,
    type=click.Path(),
    help="Output directory",
)
@click.option("--auto-severity/--no-auto-severity", default=True, show_default=True)
@click.option("--redact-fields/--no-redact-fields", default=True, show_default=True)
def build_cmd(
    finding: str,
    style: str,
    md: bool,
    pdf: bool,
    outdir: str,
    auto_severity: bool,
    redact_fields: bool,
) -> None:
    """Build Markdown/PDF report from finding YAML or JSON."""
    path = Path(finding)
    raw = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        data = yaml.safe_load(raw) or {}
    else:
        data = json.loads(raw)

    if auto_severity and not data.get("severity"):
        res = suggest_severity(
            unauthenticated=bool(data.get("unauthenticated")),
            exposes_pii=bool(data.get("exposes_pii")),
            exposes_financial=bool(data.get("exposes_financial")),
            privilege_escalation=bool(data.get("privilege_escalation")),
            rce=bool(data.get("rce")),
            easy_exploit=bool(data.get("easy_exploit", True)),
            widespread=bool(data.get("widespread")),
        )
        data["severity"] = res.rating
        data["cvss_hint"] = f"{res.score_hint}/10 — " + "; ".join(res.rationale)

    if redact_fields:
        notes = []
        for key in ("summary", "impact", "request", "response", "remediation"):
            if data.get(key):
                cleaned, fired = redact_text(str(data[key]))
                data[key] = cleaned
                if fired:
                    notes.append(f"{key}: {', '.join(fired)}")
        if data.get("steps"):
            new_steps = []
            for s in data["steps"]:
                c, f = redact_text(str(s))
                new_steps.append(c)
                if f:
                    notes.append(f"step: {', '.join(f)}")
            data["steps"] = new_steps
        if notes:
            data["redaction_notes"] = "Auto-redacted: " + "; ".join(notes)

    ctx = build_context(data)
    out_path = Path(outdir)
    out_path.mkdir(parents=True, exist_ok=True)
    slug = "".join(c if c.isalnum() or c in "-_" else "-" for c in ctx["title"].lower())[:60]

    if md:
        md_path = out_path / f"{slug}.md"
        md_path.write_text(render_markdown(ctx, style=style), encoding="utf-8")
        console.print(f"Markdown: [green]{md_path}[/green]")
    if pdf:
        pdf_path = out_path / f"{slug}.pdf"
        render_pdf(ctx, pdf_path)
        console.print(f"PDF:      [green]{pdf_path}[/green]")

    console.print(
        Panel(
            f"{ctx['title']}\nSeverity: [bold]{ctx['severity']}[/bold] | Style: {style}",
            title="disclose-cli",
        )
    )


if __name__ == "__main__":
    main()
