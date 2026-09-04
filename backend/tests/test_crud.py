from pathlib import Path

from sqlalchemy.orm import Session

from app import crud
from app.forensics.report import generate_report

SAMPLES_DIR = Path(__file__).resolve().parents[2] / "data" / "samples"


def _sample_report(name: str):  # type: ignore[no-untyped-def]
    raw = (SAMPLES_DIR / name).read_bytes()
    report = generate_report(raw, filename=name, geoip_city_db_path="/nonexistent.mmdb")
    return raw, report


def test_create_completed_analysis_persists_flat_fields(db_session: Session) -> None:
    raw, report = _sample_report("03_spf_fail_spoofed_bank.eml")
    analysis = crud.create_completed_analysis(db_session, raw=raw, filename="03.eml", report=report)

    assert analysis.status == "complete"
    assert analysis.spf_result == "fail"
    assert analysis.sha256 == report.meta.sha256
    assert analysis.from_address == "alerts@firstnational.test"
    assert analysis.hop_count == report.hop_count


def test_hops_and_anomalies_are_persisted(db_session: Session) -> None:
    raw, report = _sample_report("14_forged_received_header_private_ip_public_path.eml")
    analysis = crud.create_completed_analysis(db_session, raw=raw, filename="14.eml", report=report)

    assert len(analysis.hops) == len(report.hops)
    assert len(analysis.anomalies) == len(report.anomalies)
    bogon_hops = [h for h in analysis.hops if h.is_bogon]
    assert len(bogon_hops) >= 2


def test_highest_anomaly_severity_computed() -> None:
    from app.crud import _highest_severity
    from app.forensics.models import Anomaly

    anomalies = [
        Anomaly(type="hop_count_outlier", severity="low", hop_sequences=[], summary="", evidence=""),
        Anomaly(type="bogon_ip_in_path", severity="high", hop_sequences=[], summary="", evidence=""),
        Anomaly(type="forged_internal_origin", severity="medium", hop_sequences=[], summary="", evidence=""),
    ]
    assert _highest_severity(anomalies) == "high"


def test_highest_anomaly_severity_none_when_no_anomalies() -> None:
    from app.crud import _highest_severity

    assert _highest_severity([]) is None


def test_to_analysis_detail_round_trips_authentication(db_session: Session) -> None:
    raw, report = _sample_report("20_dmarc_fail_reject_policy.eml")
    analysis = crud.create_completed_analysis(db_session, raw=raw, filename="20.eml", report=report)
    detail = crud.to_analysis_detail(analysis)

    assert detail.authentication.spf is not None
    assert detail.authentication.spf.result == "fail"
    assert detail.authentication.dmarc_policy == "reject"
    assert len(detail.hops) == report.hop_count


def test_to_forensic_report_round_trips_for_export(db_session: Session) -> None:
    raw, report = _sample_report("13_forged_received_header_injected.eml")
    analysis = crud.create_completed_analysis(db_session, raw=raw, filename="13.eml", report=report)
    rebuilt = crud.to_forensic_report(analysis)

    assert rebuilt.hop_count == report.hop_count
    assert len(rebuilt.anomalies) == len(report.anomalies)
    assert {a.type for a in rebuilt.anomalies} == {a.type for a in report.anomalies}
    assert rebuilt.authentication.spf is not None and rebuilt.authentication.spf.result == "fail"


def test_fail_analysis_marks_status(db_session: Session) -> None:
    analysis = crud.create_pending_analysis(db_session, raw=b"junk", filename="bad.eml")
    crud.fail_analysis(db_session, analysis, "boom" * 500)
    assert analysis.status == "failed"
    assert analysis.status_detail is not None
    assert len(analysis.status_detail) <= 1024


def test_list_analyses_filters_by_status(db_session: Session) -> None:
    raw, report = _sample_report("01_clean_newsletter.eml")
    crud.create_completed_analysis(db_session, raw=raw, filename="a.eml", report=report)
    crud.create_pending_analysis(db_session, raw=b"x", filename="b.eml")

    complete_rows, complete_total = crud.list_analyses(db_session, status="complete")
    pending_rows, pending_total = crud.list_analyses(db_session, status="pending")

    assert complete_total >= 1
    assert all(r.status == "complete" for r in complete_rows)
    assert pending_total >= 1
    assert all(r.status == "pending" for r in pending_rows)


def test_list_analyses_pagination(db_session: Session) -> None:
    raw, report = _sample_report("02_clean_internal_memo.eml")
    for i in range(3):
        crud.create_completed_analysis(db_session, raw=raw, filename=f"dup{i}.eml", report=report)

    first_page, total = crud.list_analyses(db_session, limit=2, offset=0)
    second_page, _ = crud.list_analyses(db_session, limit=2, offset=2)

    assert total >= 3
    assert len(first_page) == 2
    assert len(second_page) >= 1
    assert {r.id for r in first_page}.isdisjoint({r.id for r in second_page})
