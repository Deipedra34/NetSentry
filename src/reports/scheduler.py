"""Scheduled daily/weekly reports, and rotation of old ones."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Union

logger = logging.getLogger("netsentry.reports")

# what rotation counts as a scheduled report -- on-demand reports saved to
# the same folder (report_custom_*, report_24h_*, ...) are never deleted
SCHEDULED_REPORT_PATTERNS = ("report_daily_*.pdf", "report_weekly_*.pdf")


def rotate_reports(output_dir: Union[str, Path], keep: int) -> List[Path]:
    """Deletes the oldest scheduled reports in output_dir beyond the newest
    `keep` (by modification time), returning what was deleted. keep <= 0
    keeps everything. A file that can't be deleted is logged and skipped."""
    if keep <= 0:
        return []
    folder = Path(output_dir)
    reports = {path for pattern in SCHEDULED_REPORT_PATTERNS for path in folder.glob(pattern)}
    newest_first = sorted(reports, key=lambda path: (path.stat().st_mtime, path.name), reverse=True)
    deleted: List[Path] = []
    for path in newest_first[keep:]:
        try:
            path.unlink()
        except OSError as exc:
            logger.warning("Could not delete old report %s: %s", path, exc)
            continue
        deleted.append(path)
    if deleted:
        logger.info("Deleted %d old report(s) beyond reports.keep_reports=%d", len(deleted), keep)
    return deleted
