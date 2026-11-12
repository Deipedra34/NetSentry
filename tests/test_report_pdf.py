"""Unit tests for the PDF layout (:mod:`src.reports.pdf`) and the report
generator (:mod:`src.reports.generator`)."""

from __future__ import annotations

import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, List
from unittest.mock import patch

import pytest
from reportlab import rl_config
from reportlab.platypus import Flowable, KeepTogether, Paragraph, Table

from src.config import ReportsConfig
from src.database import BlockedIP, Database, Event, ThreatIntelResult
from src.reports import daily_period, default_report_path, report_bytes, write_report
from src.reports.generator import build_report_data
from src.reports.pdf import MAX_DETAILS_LENGTH, build_story

PERIOD = daily_period(date(2026, 11, 11), timezone.utc)
GENERATED = datetime(2026, 11, 12, 8, 0, tzinfo=timezone.utc)
OPTIONAL_HEADINGS = {"Events by country", "Threat intelligence", "Blocked IPs"}
EVENT_HEADINGS = {"Events by type", "Event timeline", "Top source IPs", "Notable events"}


def at(hour: int, minute: int = 0) -> datetime:
    return datetime(2026, 11, 11, hour, minute, tzinfo=timezone.utc)


@pytest.fixture()
def db(tmp_path: Path) -> Iterator[Database]:
    database = Database(tmp_path / "reports.db")
    yield database
    database.close()


@pytest.fixture()
def uncompressed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Writes page content uncompressed, so the tests can look for text in
    the raw PDF bytes."""
    monkeypatch.setattr(rl_config, "pageCompression", 0)


def seed(db: Database, count: int = 30) -> None:
    for i in range(count):
        db.log_event(
            Event(
                event_type=("PORT_SCAN", "SYN_FLOOD", "BEACONING")[i % 3],
                source_ip=f"45.33.1.{i % 4}",
                details=f"event {i}",
                timestamp=at(i % 24, i % 60),
            )
        )


def _texts(flowables: List[Flowable]) -> List[str]:
    """Every paragraph's text in the story, including those inside
    KeepTogether groups and table cells."""
    texts: List[str] = []
    for flowable in flowables:
        if isinstance(flowable, KeepTogether):
            texts += _texts(flowable._content)
        elif isinstance(flowable, Table):
            texts += _texts([cell for row in flowable._cellvalues for cell in row])
        elif isinstance(flowable, Paragraph):
            texts.append(flowable.text)
    return texts


def _story_texts(db: Database) -> List[str]:
    return _texts(build_story(build_report_data(db, PERIOD, generated_at=GENERATED)))


def test_report_is_a_valid_pdf_with_netsentry_metadata(db: Database) -> None:
    seed(db)
    pdf = report_bytes(db, PERIOD, generated_at=GENERATED)
    assert pdf.startswith(b"%PDF-")
    assert pdf.rstrip().endswith(b"%%EOF")
    assert b"/Author (NetSentry)" in pdf
    assert b"/Creator (NetSentry)" in pdf
    assert b"/Title (NetSentry daily report: 2026-11-11)" in pdf


def test_report_credits_only_netsentry(db: Database, uncompressed: None) -> None:
    seed(db)
    pdf = report_bytes(db, PERIOD, generated_at=GENERATED)
    info = dict(re.findall(rb"/(Author|Creator|Producer) \((.*?)\) ", pdf))
    assert info[b"Author"] == info[b"Creator"] == b"NetSentry"
    assert info[b"Producer"].startswith(b"ReportLab")  # the PDF library itself
    # the only credit in the text: the title block's "by NetSentry" (the
    # footer's "Generated" line carries the page number instead)
    generated = re.findall(rb"\(Generated [^)]*\)", pdf)
    assert generated
    assert all(line.endswith(b" by NetSentry)") or b"  |  Page " in line for line in generated)


def test_footer_has_page_numbers_and_generation_time(db: Database, uncompressed: None) -> None:
    seed(db, count=60)
    pdf = report_bytes(db, PERIOD, ReportsConfig(max_notable_events=60), generated_at=GENERATED)
    pages = int(re.search(rb"/Count (\d+)", pdf).group(1))
    assert pages >= 2
    for page in range(1, pages + 1):
        assert f"Page {page} of {pages}".encode() in pdf
    assert b"Generated 2026-11-12 08:00" in pdf


def test_all_event_sections_present_with_events(db: Database) -> None:
    seed(db)
    texts = _story_texts(db)
    assert EVENT_HEADINGS <= set(texts)
    assert "No events were detected in this period." not in texts


def test_empty_database_produces_a_valid_report_saying_so(db: Database, uncompressed: None) -> None:
    pdf = report_bytes(db, PERIOD, generated_at=GENERATED)
    assert pdf.startswith(b"%PDF-")
    assert b"No events were detected in this period." in pdf
    texts = set(_story_texts(db))
    assert "Summary" in texts
    assert not texts & (EVENT_HEADINGS | OPTIONAL_HEADINGS)


def test_optional_sections_are_omitted_without_their_data(db: Database) -> None:
    seed(db)
    assert not set(_story_texts(db)) & OPTIONAL_HEADINGS


def test_optional_sections_appear_with_their_data(db: Database) -> None:
    seed(db)
    db.log_event(Event("PORT_SCAN", "45.33.1.1", "scan [GeoIP: Germany (DE)]", timestamp=at(3)))
    db.save_threat_intel(ThreatIntelResult("45.33.1.1", at(3), 87, 42, 12, 94))
    db.add_blocked_ip(BlockedIP("45.33.1.2", "SYN_FLOOD", "rule", blocked_at=at(4)))
    assert OPTIONAL_HEADINGS <= set(_story_texts(db))


def test_long_text_is_truncated_and_wraps_without_breaking_the_layout(db: Database) -> None:
    ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    unbroken = "x" * 2000
    db.log_event(Event("DATA_EXFILTRATION", ipv6, f"{unbroken} {'word ' * 2000}", timestamp=at(5)))
    texts = _story_texts(db)
    details = [t for t in texts if t.startswith("xxxx")]
    assert details and all(len(t) <= MAX_DETAILS_LENGTH for t in details)
    assert details[0].endswith("...")
    # a LayoutError would be raised here if anything didn't fit the page
    assert report_bytes(db, PERIOD, generated_at=GENERATED).startswith(b"%PDF-")


def test_markup_in_event_text_is_escaped(db: Database) -> None:
    db.log_event(Event("PORT_SCAN", "45.33.1.1", "<b>not bold</b> & <unclosed", timestamp=at(5)))
    assert report_bytes(db, PERIOD, generated_at=GENERATED).startswith(b"%PDF-")
    assert "&lt;b&gt;not bold&lt;/b&gt; &amp; &lt;unclosed" in _story_texts(db)


def test_write_report_uses_the_configured_folder_and_period_filename(db: Database, tmp_path: Path) -> None:
    settings = ReportsConfig(output_dir=str(tmp_path / "out"))
    path = write_report(db, PERIOD, settings=settings, generated_at=GENERATED)
    assert path == default_report_path(PERIOD, settings) == tmp_path / "out" / "report_daily_2026-11-11.pdf"
    assert path.read_bytes().startswith(b"%PDF-")
    assert path.stat().st_size > 0


def test_write_report_leaves_nothing_behind_when_rendering_fails(db: Database, tmp_path: Path) -> None:
    target = tmp_path / "out" / "report.pdf"
    with patch("src.reports.generator.render_pdf", side_effect=RuntimeError("boom")):
        with pytest.raises(RuntimeError):
            write_report(db, PERIOD, target)
    assert list((tmp_path / "out").iterdir()) == []


def test_table_sizes_follow_the_settings(db: Database) -> None:
    seed(db)
    data = build_report_data(db, PERIOD, ReportsConfig(max_notable_events=3, top_n_sources=2))
    assert len(data.notable_events) == 3
    assert len(data.top_sources) == 2
    assert data.generated_at.tzinfo is not None
    assert data.generated_at - datetime.now(timezone.utc) < timedelta(minutes=1)
