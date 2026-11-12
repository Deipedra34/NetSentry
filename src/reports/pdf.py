"""Lays a ReportData (src/reports/data.py) out as a PDF.

Pure reportlab: platypus flowables for the text and tables, and
reportlab's own graphics module for the charts, so no system libraries or
plotting packages are needed. build_story() turns the data into a list of
flowables (one function per section, each returning an empty list when
there's nothing to show, so optional sections drop out cleanly) and
render_pdf() writes them to a file or file-like object.

All text from the database goes through _text(), which escapes it for
reportlab's paragraph markup and truncates it, and table cells are
paragraphs, which wrap (splitting overlong words like IPv6 addresses) --
so long details can never push a table off the page.
"""

from __future__ import annotations

from typing import IO, Any, Dict, List, Optional, Union
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Flowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from src.reports.data import ReportData

AUTHOR = "NetSentry"
PAGE_SIZE = A4
MARGIN = 18 * mm
CONTENT_WIDTH = PAGE_SIZE[0] - 2 * MARGIN

ACCENT = colors.HexColor("#2f6fdb")
MUTED = colors.HexColor("#6b7280")
GRID = colors.HexColor("#d1d5db")
HEADER_BACKGROUND = colors.HexColor("#eef2f9")


def _styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("ReportTitle", parent=base["Title"], fontSize=20, leading=24, spaceAfter=4),
        "subtitle": ParagraphStyle("ReportSubtitle", parent=base["Normal"], fontSize=10.5, textColor=MUTED,
                                   alignment=1, spaceAfter=2),
        "h2": ParagraphStyle("ReportHeading", parent=base["Heading2"], fontSize=13.5, leading=17,
                             textColor=ACCENT, spaceBefore=14, spaceAfter=6),
        "body": ParagraphStyle("ReportBody", parent=base["Normal"], fontSize=10, leading=13.5),
        "note": ParagraphStyle("ReportNote", parent=base["Normal"], fontSize=8.5, leading=11, textColor=MUTED),
        "cell": ParagraphStyle("ReportCell", parent=base["Normal"], fontSize=8.5, leading=10.5),
        "cell_bold": ParagraphStyle("ReportCellBold", parent=base["Normal"], fontSize=8.5, leading=10.5,
                                    fontName="Helvetica-Bold"),
    }


STYLES = _styles()


def _text(value: Any, limit: Optional[int] = None) -> str:
    """value as safe paragraph markup, cut to `limit` characters."""
    text = str(value)
    if limit is not None and len(text) > limit:
        text = text[: limit - 3].rstrip() + "..."
    return escape(text)


def _cell(value: Any, limit: Optional[int] = 120, style: str = "cell") -> Paragraph:
    return Paragraph(_text(value, limit), STYLES[style])


def _table(rows: List[List[Any]], widths: List[float], align_right: Optional[List[int]] = None) -> Table:
    """A table with a header row; every cell is wrapped in a paragraph so
    long values wrap instead of overflowing. widths are fractions of the
    content width."""
    header = [_cell(value, style="cell_bold") for value in rows[0]]
    body = [[value if isinstance(value, Flowable) else _cell(value) for value in row] for row in rows[1:]]
    table = Table([header, *body], colWidths=[w * CONTENT_WIDTH for w in widths], repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), HEADER_BACKGROUND),
        ("LINEBELOW", (0, 0), (-1, 0), 0.8, ACCENT),
        ("LINEBELOW", (0, 1), (-1, -1), 0.25, GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    table.setStyle(TableStyle(style))
    return table


def _heading(text: str) -> Paragraph:
    return Paragraph(_text(text), STYLES["h2"])


def _change(current: int, previous: int) -> str:
    """'+12 (+40%)', '-3 (-25%)', 'no change', or '+5 (new)' when the
    previous period had none."""
    delta = current - previous
    if delta == 0:
        return "no change"
    if previous == 0:
        return f"+{delta} (new)"
    return f"{delta:+d} ({delta / previous:+.0%})"


def _title_section(data: ReportData) -> List[Flowable]:
    return [
        Spacer(1, 6 * mm),
        Paragraph(_text(data.period.title), STYLES["title"]),
        Paragraph(_text(f"Covering {data.period.describe_range()}"), STYLES["subtitle"]),
        Paragraph(
            _text(f"Generated {data.generated_at.strftime('%Y-%m-%d %H:%M')} by {AUTHOR}"),
            STYLES["subtitle"],
        ),
        Spacer(1, 4 * mm),
    ]


def _summary_section(data: ReportData) -> List[Flowable]:
    s = data.summary
    rows: List[List[Any]] = [
        ["", "This period", "Previous period", "Change"],
        ["Total events", s.total_events, s.previous_total_events,
         _change(s.total_events, s.previous_total_events)],
        ["Critical events", s.critical_events, s.previous_critical_events,
         _change(s.critical_events, s.previous_critical_events)],
        ["Distinct source IPs", s.distinct_sources, s.previous_distinct_sources,
         _change(s.distinct_sources, s.previous_distinct_sources)],
    ]
    flowables: List[Flowable] = [_heading("Summary")]
    if data.is_empty:
        flowables.append(Paragraph("No events were detected in this period.", STYLES["body"]))
        flowables.append(Spacer(1, 3 * mm))
    flowables.append(_table(rows, [0.34, 0.2, 0.22, 0.24]))
    flowables.append(Spacer(1, 2 * mm))
    flowables.append(
        Paragraph(
            _text(
                f"The previous period is the {data.period.previous().describe_range()} window "
                "of the same length. Critical events are the event types NetSentry sends "
                "notifications for."
            ),
            STYLES["note"],
        )
    )
    return flowables


def build_story(data: ReportData) -> List[Flowable]:
    """Every section of the report, in order, as reportlab flowables."""
    story: List[Flowable] = []
    for section in (_title_section, _summary_section):
        story.extend(section(data))
    return story


def render_pdf(data: ReportData, target: Union[str, IO[bytes]]) -> None:
    """Writes the report for `data` as a PDF to a path or binary file."""
    document = SimpleDocTemplate(
        target,
        pagesize=PAGE_SIZE,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=MARGIN,
        title=data.period.title,
        author=AUTHOR,
        creator=AUTHOR,
        subject=f"Detected events, {data.period.describe_range()}",
    )
    document.build(build_story(data))
