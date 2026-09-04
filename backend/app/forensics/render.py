"""Human-readable text rendering of a ForensicReport.

Shared by the CLI (prints it) and the API's text-export endpoint (returns
it as a download) so the two never drift out of sync with each other.
"""

from app.forensics.models import ForensicReport

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def render_text_report(report: ForensicReport) -> str:
    lines: list[str] = []
    m = report.meta
    a = report.authentication

    _section(lines, "TVA FORENSIC REPORT")
    lines.append(f"file:              {report.filename}")
    lines.append(f"sha256:            {m.sha256}")
    lines.append(f"verdict:           {report.risk.verdict.upper()}  (risk score {report.risk.score}/100)")
    lines.append(f"parse confidence:  {m.parse_confidence:.0%}")
    if m.issues:
        lines.append(f"parse issues:      {len(m.issues)}")
        for issue in m.issues:
            lines.append(f"  - [{issue.field}] {issue.detail}")

    _section(lines, "MESSAGE")
    lines.append(f"from:        {m.from_display_name or ''} <{m.from_address or 'unknown'}>")
    lines.append(f"to:          {', '.join(m.to_addresses) or 'unknown'}")
    lines.append(f"subject:     {m.subject or ''}")
    lines.append(f"date:        {m.date_raw or 'unknown'}")
    lines.append(f"message-id:  {m.message_id or 'unknown'}")
    lines.append(f"attachments: {', '.join(m.attachment_names) if m.has_attachments else 'none'}")

    _section(lines, "AUTHENTICATION (SPF / DKIM / DMARC)")
    if a.source == "unavailable":
        lines.append("no Authentication-Results header present -- unable to determine SPF/DKIM/DMARC")
    else:
        for label, result in (("SPF", a.spf), ("DKIM", a.dkim), ("DMARC", a.dmarc)):
            if result is None:
                lines.append(f"{label:6s} unknown (not reported by boundary MTA)")
            else:
                reason = f" -- {result.reason}" if result.reason else ""
                lines.append(f"{label:6s} {result.result.upper()}{reason}")
        lines.append(f"dmarc policy published: {a.dmarc_policy}")
    if a.dkim_signature_present:
        expired = "EXPIRED" if a.dkim_signature_expired else "not expired"
        lines.append(f"dkim signature:    present, {expired}")

    _section(lines, f"RELAY CHAIN ({report.hop_count} hops, earliest -> latest)")
    if not report.hops:
        lines.append("no Received headers found")
    for hop in report.hops:
        geo = ""
        if hop.enrichment_source == "geolite2-local":
            geo = f"  [{hop.city or '?'}, {hop.country or '?'} | AS{hop.asn or '?'} {hop.asn_org or ''}]"
        bogon = "  [BOGON]" if hop.is_bogon else ""
        ts = hop.timestamp.isoformat() if hop.timestamp else (hop.timestamp_raw or "unknown")
        lines.append(
            f"  #{hop.sequence}  from={hop.from_host or '?'} ({hop.from_ip or 'no-ip'})  "
            f"by={hop.by_host or '?'}  with={hop.protocol or '?'}  at={ts}"
            f"  conf={hop.parse_confidence:.0%}{geo}{bogon}"
        )

    _section(lines, f"ANOMALIES ({len(report.anomalies)})")
    if not report.anomalies:
        lines.append("none detected")
    for anomaly in sorted(report.anomalies, key=lambda a: _SEVERITY_ORDER.get(a.severity, 9)):
        lines.append(f"  [{anomaly.severity.upper():8s}] {anomaly.type}: {anomaly.summary}")
        lines.append(f"             evidence: {anomaly.evidence}")

    _section(lines, f"RISK SCORE: {report.risk.score}/100 -- {report.risk.verdict.upper()}")
    if not report.risk.factors:
        lines.append("no contributing factors -- nothing raised the score above zero")
    for factor in report.risk.factors:
        lines.append(f"  +{factor.weight:<3d} [{factor.category}] {factor.name}")
        lines.append(f"             evidence: {factor.evidence}")

    if report.sender_domain_intel:
        _section(lines, "SENDER DOMAIN INTEL")
        di = report.sender_domain_intel
        if di.source == "unavailable":
            lines.append(f"domain: {di.domain}  age: unavailable ({di.detail or 'no data'})")
        else:
            badge = "[cached]" if di.source == "cached" else "[live]"
            lines.append(f"domain: {di.domain}  age: {di.age_days} days {badge}")

    _section(lines, "AI & CONTENT SIGNALS (Phase 4)")
    ai = report.ai_signals
    if ai.phishing.source == "onnx-model":
        prob = ai.phishing.phishing_probability or 0.0
        lines.append(f"phishing classifier: {(ai.phishing.label or '?').upper()} (p={prob:.0%})")
    else:
        lines.append(f"phishing classifier: unavailable ({ai.phishing.detail or 'no model'})")

    if ai.sender_domain_lookalike and ai.sender_domain_lookalike.matches:
        lines.append(f"sender domain lookalike matches ({ai.sender_domain_lookalike.domain}):")
        for match in ai.sender_domain_lookalike.matches:
            lines.append(f"  - {match.matched_brand} via {match.method}: {match.detail}")
    else:
        lines.append("sender domain lookalike: no matches")

    if ai.urls.urls:
        lines.append(f"links found: {len(ai.urls.urls)}")
        for url in ai.urls.urls:
            flags = []
            if url.is_ip_literal:
                flags.append("IP-literal")
            if url.anchor_text_mismatch:
                flags.append(f"anchor claims {url.anchor_claimed_domain!r}")
            if url.unwrapped_target:
                flags.append(f"unwraps to {url.unwrapped_target}")
            if url.lookalike and url.lookalike.matches:
                flags.append(f"lookalike for {url.lookalike.matches[0].matched_brand}")
            flag_str = f"  [{', '.join(flags)}]" if flags else ""
            lines.append(f"  - {url.raw_url}{flag_str}")
    else:
        lines.append("links found: none")

    if ai.ai_text.source == "onnx-model":
        flag = " [worth a second look]" if ai.ai_text.low_perplexity_flag else ""
        lines.append(f"ai-text perplexity: {ai.ai_text.perplexity:.1f}{flag} (weak, informational signal only)")
    else:
        lines.append(f"ai-text scoring: unavailable ({ai.ai_text.detail or 'no model'})")

    lines.append("")
    return "\n".join(lines)


def _section(lines: list[str], title: str) -> None:
    lines.append(f"\n== {title} " + "=" * max(0, 70 - len(title)))
