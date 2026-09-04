"""The court-usable forensic PDF report: case ID, chain-of-custody
metadata, full relay analysis, an evidenced indicator table, a relay-path
map snapshot, and an analyst notes field.

Built with ReportLab rather than WeasyPrint -- WeasyPrint's system
dependency chain (Pango, Cairo, GDK-Pixbuf) is exactly the kind of thing
that makes a Docker image fragile to build reproducibly; ReportLab is
pure Python, so the api/worker images stay simple. "Boring, proven"
over "nicer HTML-to-PDF templating," per the project's own engineering
rules.

The map snapshot is a plain lat/long scatter drawn with ReportLab's own
drawing primitives (no matplotlib, no map-tile data bundled a second time
just for the PDF) -- honest about what it is: relative hop positions on a
simple grid, not a full illustrated world map. When no hop has
geolocation data (the common case without a licensed GeoLite2 database),
that section says so plainly instead of rendering an empty box.
"""

from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.attribution.ioc import Ioc
from app.forensics.models import ForensicReport

_VERDICT_COLORS = {
    "clean": colors.HexColor("#16a34a"),
    "suspicious": colors.HexColor("#d97706"),
    "malicious": colors.HexColor("#dc2626"),
}


def generate_pdf_report(
    report: ForensicReport, *, case_id: str, iocs: list[Ioc], analyst_notes: str | None
) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=LETTER,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
        leftMargin=0.6 * inch,
        rightMargin=0.6 * inch,
        title=f"TVA Forensic Report {case_id}",
    )
    styles = getSampleStyleSheet()
    story = []

    story.extend(_header(report, case_id, styles))
    story.extend(_chain_of_custody(report, case_id, styles))
    story.extend(_verdict_section(report, styles))
    story.extend(_authentication_section(report, styles))
    story.extend(_attribution_section(report, styles))
    story.extend(_relay_chain_section(report, styles))
    story.extend(_map_snapshot_section(report, styles))
    story.extend(_indicator_section(report, styles))
    story.extend(_ioc_section(iocs, styles))
    story.extend(_analyst_notes_section(analyst_notes, styles))

    doc.build(story)
    return buffer.getvalue()


def _header(report: ForensicReport, case_id: str, styles: dict) -> list:  # type: ignore[type-arg]
    title_style = ParagraphStyle(
        "TVATitle", parent=styles["Title"], textColor=colors.HexColor("#0f172a")
    )
    elements = [
        Paragraph("TVA — Threat Variance Authority", title_style),
        Paragraph("Forensic Evidence Report — For All Mail. Always.", styles["Normal"]),
        Spacer(1, 0.15 * inch),
        Paragraph(f"<b>Case ID:</b> {case_id}", styles["Normal"]),
        Paragraph(f"<b>Generated:</b> {report.generated_at.isoformat()}", styles["Normal"]),
        Spacer(1, 0.2 * inch),
    ]
    return elements


def _chain_of_custody(report: ForensicReport, case_id: str, styles: dict) -> list:  # type: ignore[type-arg]
    m = report.meta
    rows = [
        ["Field", "Value"],
        ["Case ID", case_id],
        ["Original filename", report.filename],
        ["SHA-256 of original message", m.sha256],
        ["Source format", m.source_format],
        ["Parse confidence", f"{m.parse_confidence:.0%}"],
        ["From", f"{m.from_display_name or ''} <{m.from_address or 'unknown'}>"],
        ["Subject", m.subject or "(none)"],
        ["Message Date header", m.date_raw or "unknown"],
        ["Report generated at", report.generated_at.isoformat()],
    ]
    return [
        Paragraph("Chain of Custody", styles["Heading2"]),
        _table(rows, col_widths=[2.2 * inch, 4.3 * inch]),
        Spacer(1, 0.2 * inch),
    ]


def _verdict_section(report: ForensicReport, styles: dict) -> list:  # type: ignore[type-arg]
    risk = report.risk
    color = _VERDICT_COLORS.get(risk.verdict, colors.black)
    verdict_style = ParagraphStyle("Verdict", parent=styles["Heading1"], textColor=color)
    return [
        Paragraph("Verdict", styles["Heading2"]),
        Paragraph(f"{risk.verdict.upper()} — risk score {risk.score}/100", verdict_style),
        Spacer(1, 0.15 * inch),
    ]


def _authentication_section(report: ForensicReport, styles: dict) -> list:  # type: ignore[type-arg]
    a = report.authentication
    rows = [["Mechanism", "Result", "Reason"]]
    for label, result in (("SPF", a.spf), ("DKIM", a.dkim), ("DMARC", a.dmarc)):
        if result is None:
            rows.append([label, "unknown", "not reported by boundary MTA"])
        else:
            rows.append([label, result.result.upper(), result.reason or ""])
    rows.append(["DMARC policy published", a.dmarc_policy, ""])
    return [
        Paragraph("Authentication (SPF / DKIM / DMARC)", styles["Heading2"]),
        _table(rows, col_widths=[1.5 * inch, 1.2 * inch, 3.8 * inch]),
        Spacer(1, 0.2 * inch),
    ]


def _attribution_section(report: ForensicReport, styles: dict) -> list:  # type: ignore[type-arg]
    attr = report.attribution
    lines = [
        f"<b>Confidence:</b> {attr.confidence.upper()}",
    ]
    if attr.origin_ip:
        lines.append(f"<b>Candidate origin IP:</b> {attr.origin_ip} (relay hop #{attr.origin_hop_sequence})")
    if attr.asn_org:
        lines.append(f"<b>Network:</b> {attr.asn_org} (AS{attr.asn}), {attr.country or 'unknown country'}")
    return [
        Paragraph("Origin Attribution", styles["Heading2"]),
        *[Paragraph(line, styles["Normal"]) for line in lines],
        Spacer(1, 0.05 * inch),
        Paragraph(f"<i>Reasoning:</i> {attr.reasoning}", styles["Normal"]),
        Spacer(1, 0.2 * inch),
    ]


def _relay_chain_section(report: ForensicReport, styles: dict) -> list:  # type: ignore[type-arg]
    rows = [["#", "From", "By", "IP", "Timestamp", "Location"]]
    for hop in report.hops:
        location = f"{hop.city or '?'}, {hop.country or '?'}" if hop.enrichment_source == "geolite2-local" else "—"
        ts = hop.timestamp.isoformat() if hop.timestamp else (hop.timestamp_raw or "unknown")
        rows.append(
            [
                str(hop.sequence) + (" ⚠" if hop.is_bogon else ""),
                hop.from_host or "?",
                hop.by_host or "?",
                hop.from_ip or "—",
                ts,
                location,
            ]
        )
    return [
        Paragraph(f"Relay Chain ({report.hop_count} hops, earliest → latest)", styles["Heading2"]),
        _table(rows, col_widths=[0.4 * inch, 1.5 * inch, 1.5 * inch, 1.1 * inch, 1.5 * inch, 0.9 * inch], font_size=7),
        Spacer(1, 0.2 * inch),
    ]


def _map_snapshot_section(report: ForensicReport, styles: dict) -> list:  # type: ignore[type-arg]
    geo_hops = [h for h in report.hops if h.latitude is not None and h.longitude is not None]
    elements = [Paragraph("Relay Path — Map Snapshot", styles["Heading2"])]
    if not geo_hops:
        elements.append(
            Paragraph(
                "No hop geolocation available -- GeoIP enrichment requires a licensed "
                "GeoLite2-City.mmdb (see data/geoip/README.md). The relay chain above was "
                "still fully reconstructed and analyzed without it.",
                styles["Normal"],
            )
        )
        elements.append(Spacer(1, 0.2 * inch))
        return elements

    from reportlab.graphics.shapes import Circle, Drawing, Line, String

    width, height = 460, 220
    drawing = Drawing(width, height)
    lons = [h.longitude for h in geo_hops if h.longitude is not None]
    lats = [h.latitude for h in geo_hops if h.latitude is not None]
    lon_min, lon_max = min(lons) - 5, max(lons) + 5
    lat_min, lat_max = min(lats) - 5, max(lats) + 5
    lon_span = max(lon_max - lon_min, 1e-6)
    lat_span = max(lat_max - lat_min, 1e-6)

    def project(lon: float, lat: float) -> tuple[float, float]:
        x = 20 + (lon - lon_min) / lon_span * (width - 40)
        y = 20 + (lat - lat_min) / lat_span * (height - 40)
        return x, y

    points = [project(h.longitude, h.latitude) for h in geo_hops if h.longitude is not None and h.latitude is not None]  # type: ignore[arg-type]
    for (x1, y1), (x2, y2) in zip(points, points[1:], strict=False):
        drawing.add(Line(x1, y1, x2, y2, strokeColor=colors.HexColor("#38bdf8"), strokeWidth=1.5))
    for hop, (x, y) in zip(geo_hops, points, strict=False):
        color = colors.HexColor("#dc2626") if hop.is_bogon else colors.HexColor("#38bdf8")
        drawing.add(Circle(x, y, 4, fillColor=color, strokeColor=colors.white))
        drawing.add(String(x + 6, y + 4, f"#{hop.sequence} {hop.city or hop.country or ''}", fontSize=6))

    elements.append(drawing)
    elements.append(
        Paragraph(
            "Simplified relative-position plot (longitude/latitude grid, not an illustrated "
            "world map); red markers indicate hops flagged as bogon/private addresses.",
            styles["Normal"],
        )
    )
    elements.append(Spacer(1, 0.2 * inch))
    return elements


def _indicator_section(report: ForensicReport, styles: dict) -> list:  # type: ignore[type-arg]
    rows = [["Weight", "Category", "Factor", "Evidence"]]
    for factor in sorted(report.risk.factors, key=lambda f: f.weight, reverse=True):
        rows.append([f"+{factor.weight}", factor.category, factor.name, factor.evidence])
    if len(rows) == 1:
        rows.append(["—", "—", "No contributing factors", "Nothing raised the score above zero"])
    return [
        Paragraph("Indicator Breakdown", styles["Heading2"]),
        _table(rows, col_widths=[0.6 * inch, 1.1 * inch, 1.8 * inch, 3.0 * inch], font_size=7),
        Spacer(1, 0.2 * inch),
    ]


def _ioc_section(iocs: list[Ioc], styles: dict) -> list:  # type: ignore[type-arg]
    rows = [["Type", "Value", "Context"]]
    for ioc in iocs:
        rows.append([ioc.type, ioc.value, ioc.context])
    if len(rows) == 1:
        rows.append(["—", "No indicators extracted", "—"])
    return [
        Paragraph(f"Indicators of Compromise ({len(iocs)})", styles["Heading2"]),
        _table(rows, col_widths=[0.8 * inch, 2.3 * inch, 3.4 * inch], font_size=7),
        Spacer(1, 0.2 * inch),
    ]


def _analyst_notes_section(analyst_notes: str | None, styles: dict) -> list:  # type: ignore[type-arg]
    return [
        Paragraph("Analyst Notes", styles["Heading2"]),
        Paragraph(analyst_notes or "<i>No notes recorded.</i>", styles["Normal"]),
    ]


def _table(rows: list[list[str]], col_widths: list[float], font_size: int = 8) -> Table:
    table = Table(rows, colWidths=col_widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), font_size),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
            ]
        )
    )
    return table
