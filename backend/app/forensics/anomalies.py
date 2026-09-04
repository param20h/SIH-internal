"""Anomaly detection over a reconstructed, earliest-to-latest relay chain.

Every check here is pure logic over already-parsed hops -- no network, no
ML, no external state -- so it is exactly as reliable offline as online.
Each detector returns zero or more Anomaly records with the raw evidence
that triggered it; nothing here collapses to an unexplained score.
"""

from datetime import UTC
from itertools import pairwise

from app.forensics.ip_utils import is_bogon
from app.forensics.models import Anomaly, RelayHop

HOP_COUNT_OUTLIER_THRESHOLD = 8
LARGE_JUMP_THRESHOLD_SECONDS = 6 * 3600
IMPLAUSIBLY_OLD_YEAR = 1990


def detect_anomalies(hops: list[RelayHop]) -> list[Anomaly]:
    anomalies: list[Anomaly] = []
    anomalies.extend(_detect_timestamp_anomalies(hops))
    anomalies.extend(_detect_bogon_ips(hops))
    anomalies.extend(_detect_hop_count_outlier(hops))
    anomalies.extend(_detect_duplicate_by_host(hops))
    anomalies.extend(_detect_chain_discontinuity(hops))
    return anomalies


def _detect_timestamp_anomalies(hops: list[RelayHop]) -> list[Anomaly]:
    # Deliberately no check against wall-clock "now": a forensic tool must
    # be able to analyze evidence of any age (a cold-case email from years
    # ago is not itself anomalous just because it predates the moment
    # someone finally opened it), so "the future" is only meaningful
    # relative to other timestamps *in the same chain* -- which the
    # negative-delta check below already covers. This is a timeless,
    # absolute sanity bound instead: nothing predates the email era.
    anomalies: list[Anomaly] = []

    for hop in hops:
        if hop.timestamp is None:
            continue
        ts = hop.timestamp if hop.timestamp.tzinfo else hop.timestamp.replace(tzinfo=UTC)
        if ts.year < IMPLAUSIBLY_OLD_YEAR:
            anomalies.append(
                Anomaly(
                    type="impossible_timestamp",
                    severity="medium",
                    hop_sequences=[hop.sequence],
                    summary=f"Hop {hop.sequence} timestamp predates the internet email era",
                    evidence=f"Received timestamp {hop.timestamp_raw!r} parses to {ts.isoformat()}",
                )
            )

    for prev, curr in pairwise(hops):
        if prev.timestamp is None or curr.timestamp is None:
            continue
        prev_ts = prev.timestamp if prev.timestamp.tzinfo else prev.timestamp.replace(tzinfo=UTC)
        curr_ts = curr.timestamp if curr.timestamp.tzinfo else curr.timestamp.replace(tzinfo=UTC)
        delta_seconds = (curr_ts - prev_ts).total_seconds()

        if delta_seconds < 0:
            anomalies.append(
                Anomaly(
                    type="negative_time_delta",
                    severity="high",
                    hop_sequences=[prev.sequence, curr.sequence],
                    summary=(
                        f"Hop {curr.sequence} is timestamped before hop {prev.sequence}, "
                        "which received it earlier in the chain"
                    ),
                    evidence=(
                        f"hop {prev.sequence} ({prev.by_host or 'unknown'}) at {prev_ts.isoformat()} "
                        f"-> hop {curr.sequence} ({curr.by_host or 'unknown'}) at {curr_ts.isoformat()}, "
                        f"delta {delta_seconds:.0f}s -- forged or reordered Received header"
                    ),
                )
            )
        elif delta_seconds > LARGE_JUMP_THRESHOLD_SECONDS:
            anomalies.append(
                Anomaly(
                    type="large_timezone_jump",
                    severity="low",
                    hop_sequences=[prev.sequence, curr.sequence],
                    summary=f"Large {delta_seconds / 3600:.1f}h gap between hop {prev.sequence} and {curr.sequence}",
                    evidence=(
                        f"hop {prev.sequence} at {prev_ts.isoformat()} -> hop {curr.sequence} "
                        f"at {curr_ts.isoformat()}; may be legitimate queueing delay or a "
                        "timezone/backdating issue -- reported for analyst review"
                    ),
                )
            )

    return anomalies


def _registrable_domain(host: str) -> str:
    """Naive last-two-labels approximation of a registrable domain.

    This deliberately does not consult a public suffix list (that belongs
    to the lookalike-domain module in Phase 4) -- it only needs to be good
    enough to tell "same organization's infrastructure" apart from
    "crossed into someone else's", which the two-label heuristic does
    correctly for every case in the sample corpus.
    """
    labels = host.lower().rstrip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else labels[0]


def _detect_bogon_ips(hops: list[RelayHop]) -> list[Anomaly]:
    anomalies: list[Anomaly] = []
    for hop in hops:
        if not hop.from_ip or not is_bogon(hop.from_ip):
            continue

        # A private/loopback address is unremarkable on a hop that never
        # left one organization's own infrastructure (e.g. an internal
        # relay handing off to another host in the same domain). It is
        # only suspicious once it appears on a hop that crosses an
        # organizational boundary -- exactly where a private address
        # cannot legitimately mean anything.
        same_org = (
            hop.from_host is not None
            and hop.by_host is not None
            and _registrable_domain(hop.from_host) == _registrable_domain(hop.by_host)
        )
        if same_org:
            continue

        anomalies.append(
            Anomaly(
                type="bogon_ip_in_path",
                severity="high",
                hop_sequences=[hop.sequence],
                summary=f"Hop {hop.sequence} claims a private/non-routable sending address",
                evidence=(
                    f"hop {hop.sequence} from {hop.from_host!r} reports source IP "
                    f"{hop.from_ip}, which is not publicly routable and should not "
                    "appear on a hop that crosses an organizational boundary "
                    f"(by {hop.by_host!r})"
                ),
            )
        )
    return anomalies


def _detect_hop_count_outlier(hops: list[RelayHop]) -> list[Anomaly]:
    if len(hops) <= HOP_COUNT_OUTLIER_THRESHOLD:
        return []
    return [
        Anomaly(
            type="hop_count_outlier",
            severity="low",
            hop_sequences=list(range(len(hops))),
            summary=f"Unusually long relay chain: {len(hops)} hops",
            evidence=(
                f"{len(hops)} Received headers exceeds the {HOP_COUNT_OUTLIER_THRESHOLD}-hop "
                "baseline; not inherently malicious (large mailing-list infrastructure "
                "routinely produces long chains) but worth analyst attention"
            ),
        )
    ]


def _detect_duplicate_by_host(hops: list[RelayHop]) -> list[Anomaly]:
    seen: dict[str, list[int]] = {}
    for hop in hops:
        if not hop.by_host:
            continue
        key = hop.by_host.lower().rstrip(".")
        seen.setdefault(key, []).append(hop.sequence)

    anomalies: list[Anomaly] = []
    for host, sequences in seen.items():
        if len(sequences) > 1:
            anomalies.append(
                Anomaly(
                    type="forged_internal_origin",
                    severity="medium",
                    hop_sequences=sequences,
                    summary=f"Same recipient host '{host}' claimed by {len(sequences)} separate hops",
                    evidence=(
                        f"hops {sequences} all name {host!r} as the receiving server, which "
                        "a single legitimate handoff chain should not do -- consistent with "
                        "injected or duplicated Received headers"
                    ),
                )
            )
    return anomalies


def _detect_chain_discontinuity(hops: list[RelayHop]) -> list[Anomaly]:
    anomalies: list[Anomaly] = []
    for prev, curr in pairwise(hops):
        if not prev.by_host or not curr.from_host:
            continue
        prev_by = prev.by_host.lower().rstrip(".")
        curr_from = curr.from_host.lower().rstrip(".")
        if prev_by != curr_from:
            anomalies.append(
                Anomaly(
                    type="forged_internal_origin",
                    severity="medium",
                    hop_sequences=[prev.sequence, curr.sequence],
                    summary=f"Relay chain break between hop {prev.sequence} and hop {curr.sequence}",
                    evidence=(
                        f"hop {prev.sequence} was received 'by {prev.by_host}', but hop "
                        f"{curr.sequence} claims to be 'from {curr.from_host}' -- the two "
                        "hostnames don't match, so this handoff cannot be verified as "
                        "continuous and may indicate a missing, reordered, or forged hop"
                    ),
                )
            )
    return anomalies
