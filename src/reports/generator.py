"""The one entry point every report goes through -- CLI, dashboard and
scheduler alike: collect the data for a period, lay it out, write it."""

from __future__ import annotations

import io
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional, Union

from src.config import ReportsConfig
from src.database import Database
from src.reports.data import ReportData, ReportPeriod, collect_report_data
from src.reports.pdf import render_pdf


def build_report_data(
    database: Database,
    period: ReportPeriod,
    settings: Optional[ReportsConfig] = None,
    generated_at: Optional[datetime] = None,
) -> ReportData:
    """Everything the report for `period` shows, with the table sizes from
    `settings` (the config's reports section; defaults if omitted)."""
    settings = settings or ReportsConfig()
    return collect_report_data(
        database,
        period,
        max_notable_events=settings.max_notable_events,
        top_n_sources=settings.top_n_sources,
        generated_at=generated_at,
    )


def report_bytes(
    database: Database,
    period: ReportPeriod,
    settings: Optional[ReportsConfig] = None,
    generated_at: Optional[datetime] = None,
) -> bytes:
    """The report for `period` as PDF bytes, without touching the disk."""
    buffer = io.BytesIO()
    render_pdf(build_report_data(database, period, settings, generated_at), buffer)
    return buffer.getvalue()


def default_report_path(period: ReportPeriod, settings: Optional[ReportsConfig] = None) -> Path:
    """Where a report for `period` goes unless told otherwise: the
    configured output_dir, under the period's filename."""
    settings = settings or ReportsConfig()
    return Path(settings.output_dir) / period.filename


def write_report(
    database: Database,
    period: ReportPeriod,
    path: Union[str, Path, None] = None,
    settings: Optional[ReportsConfig] = None,
    generated_at: Optional[datetime] = None,
) -> Path:
    """Writes the report for `period` to `path` (default_report_path() if
    omitted), creating its folder if needed, and returns the path.

    The PDF is rendered into a temporary file next to the target and only
    renamed into place once complete, so a failure halfway never leaves a
    truncated report behind -- which the scheduler would otherwise mistake
    for one it has already generated."""
    target = Path(path) if path is not None else default_report_path(period, settings)
    target.parent.mkdir(parents=True, exist_ok=True)
    data = build_report_data(database, period, settings, generated_at)
    handle, temporary = tempfile.mkstemp(prefix=".report-", suffix=".pdf.tmp", dir=target.parent)
    try:
        with os.fdopen(handle, "wb") as stream:
            render_pdf(data, stream)
        os.replace(temporary, target)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    return target
