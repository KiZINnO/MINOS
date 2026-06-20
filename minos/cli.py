"""CLI entry point for MINOS — Auto-Triage SOC Bot."""

import asyncio
import logging
import sys
from pathlib import Path

import click
from dotenv import load_dotenv

from .extractor import extract_iocs
from .evtx_parser import parse_evtx_file
from .formatter import format_json, format_markdown
from .models import TriageReport
from .scorer import score_report
from .threat_intel import query_all

logger = logging.getLogger(__name__)


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@click.command()
@click.argument("input", type=click.Path(exists=True), required=False)
@click.option(
    "--text", "-t",
    default=None,
    help="Raw log text to triage (alternative to providing a file).",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    help="Write report to file instead of stdout.",
)
@click.option(
    "--format", "-f",
    "output_format",
    type=click.Choice(["markdown", "json"], case_sensitive=False),
    default="markdown",
    help="Output format: 'markdown' (default) or 'json'.",
)
@click.option(
    "--no-intel",
    is_flag=True,
    default=False,
    help="Skip threat intel lookups (extract IoCs only).",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable debug logging.",
)
def main(
    input: str | None,
    text: str | None,
    output: str | None,
    output_format: str,
    no_intel: bool,
    verbose: bool,
) -> None:
    """MINOS — Auto-Triage SOC Bot.

    Takes a security log and produces a formatted triage report.

    \b
    Examples:
      minos sysmon_events.txt
      minos sysmon_events.txt -f json -o report.json
      minos -t "Suspicious connection from 45.33.32.156 to evil.com" --no-intel
    """
    load_dotenv()
    _setup_logging(verbose)

    # ── Step 1: Load input ────────────────────────────────────────────
    if text:
        raw_text: str | None = text
        iocs = extract_iocs(raw_text, deduplicate=True)
    elif input and input.endswith(".evtx"):
        # Binary EVTX — use structured Sysmon EventID parser
        raw_text = None  # evtx is binary, no source text to display
        iocs = parse_evtx_file(input)
    elif input:
        raw_text = Path(input).read_text(encoding="utf-8")
        iocs = extract_iocs(raw_text, deduplicate=True)
    else:
        click.echo("Error: Provide a file path or use --text for inline input.", err=True)
        sys.exit(1)

    click.echo(f"[*] Extracted {len(iocs)} unique IoCs.", err=True)

    if not iocs:
        click.echo("No IoCs found in the input.", err=True)
        report = TriageReport(total_iocs=0, unique_iocs=0)
    else:
        for ioc in iocs:
            logger.info("Found %s: %s", ioc.ioc_type.value, ioc.value)

        # ── Step 3: Threat Intel lookups ──────────────────────────────
        results = []
        if not no_intel:
            click.echo("[*] Querying threat intelligence sources...", err=True)
            results = asyncio.run(query_all(iocs))
            click.echo(f"[*] Received {len(results)} results.", err=True)
        else:
            click.echo("[*] Skipping threat intel (--no-intel flag set).", err=True)

        # ── Step 4: Score ─────────────────────────────────────────────
        report = TriageReport(
            iocs=iocs,
            results=results,
            total_iocs=len(iocs),  # after dedup
            unique_iocs=len(iocs),
        )
        report = score_report(report)
        logger.info("Overall risk: %s", report.overall_risk.value)

    # ── Step 5: Format & output ──────────────────────────────────────
    if output_format == "json":
        formatted = format_json(report, pretty=True)
    else:
        formatted = format_markdown(report, source_text=raw_text)

    if output:
        Path(output).write_text(formatted, encoding="utf-8")
        click.echo(f"[*] Report written to {output}", err=True)
    else:
        click.echo(formatted)


if __name__ == "__main__":
    main()
