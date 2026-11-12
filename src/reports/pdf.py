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

import math
from typing import IO, Any, Dict, List, Optional, Tuple, Union
from xml.sax.saxutils import escape

from reportlab.graphics.charts.barcharts import HorizontalBarChart, VerticalBarChart
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Flowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from src.reports.data import ReportData, Timeline

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


def _value_axis(axis: Any, maximum: int) -> None:
    """Whole-number ticks from 0, about five of them -- event counts are
    integers, so 0.5-steps would just be confusing."""
    step = max(1, math.ceil(maximum / 5))
    magnitude = 10 ** max(0, len(str(step)) - 1)
    step = math.ceil(step / magnitude) * magnitude
    axis.valueMin = 0
    axis.valueStep = step
    axis.valueMax = max(step, math.ceil(maximum / step) * step)
    axis.labels.fontName = "Helvetica"
    axis.labels.fontSize = 7
    axis.labelTextFormat = "%d"


def _type_chart(counts: List[Tuple[str, int]]) -> Drawing:
    """Horizontal bars, busiest type at the top."""
    bar_height = 13
    label_width = 115
    drawing = Drawing(CONTENT_WIDTH, len(counts) * bar_height + 24)
    chart = HorizontalBarChart()
    chart.x = label_width
    chart.y = 16
    chart.width = CONTENT_WIDTH - label_width - 25
    chart.height = len(counts) * bar_height
    # the category axis runs bottom-up, so reverse to put the busiest first
    chart.data = [[count for _, count in reversed(counts)]]
    chart.categoryAxis.categoryNames = [name for name, _ in reversed(counts)]
    chart.categoryAxis.labels.fontName = "Helvetica"
    chart.categoryAxis.labels.fontSize = 7
    chart.categoryAxis.labels.boxAnchor = "e"
    chart.categoryAxis.strokeColor = GRID
    chart.valueAxis.strokeColor = GRID
    _value_axis(chart.valueAxis, max(count for _, count in counts))
    chart.bars[0].fillColor = ACCENT
    chart.bars[0].strokeColor = None
    chart.barLabelFormat = "%d"
    chart.barLabels.fontName = "Helvetica"
    chart.barLabels.fontSize = 7
    chart.barLabels.boxAnchor = "w"
    chart.barLabels.dx = 3
    drawing.add(chart)
    return drawing


def _types_section(data: ReportData) -> List[Flowable]:
    if data.is_empty:
        return []
    total = data.summary.total_events
    # most events first; equal counts keep the authoritative EVENT_TYPES order
    counts = sorted(
        ((event_type, count) for event_type, count in data.by_type.items() if count),
        key=lambda item: -item[1],
    )
    rows: List[List[Any]] = [["Event type", "Events", "Share"]]
    rows += [[event_type, count, f"{count / total:.1%}"] for event_type, count in counts]
    quiet = sum(1 for count in data.by_type.values() if not count)
    flowables: List[Flowable] = [
        _heading("Events by type"),
        _type_chart(counts),
        Spacer(1, 3 * mm),
        _table(rows, [0.5, 0.25, 0.25]),
    ]
    if quiet:
        flowables.append(Spacer(1, 1.5 * mm))
        flowables.append(
            Paragraph(_text(f"{quiet} other event types had no events in this period."), STYLES["note"])
        )
    return flowables


# the most bucket labels the timeline's x axis shows before thinning them out
MAX_TIMELINE_LABELS = 8


def _bucket_label(timeline: Timeline, index: int) -> str:
    start = timeline.starts[index]
    if timeline.bucket_seconds <= 3600:
        return start.strftime("%H:%M")
    if timeline.bucket_seconds < 86400:
        return start.strftime("%b %d\n%H:%M")
    return start.strftime("%b %d")


def _timeline_chart(timeline: Timeline) -> Drawing:
    count = len(timeline.counts)
    every = max(1, math.ceil(count / MAX_TIMELINE_LABELS))
    drawing = Drawing(CONTENT_WIDTH, 158)
    chart = VerticalBarChart()
    chart.x = 30
    chart.y = 36
    chart.width = CONTENT_WIDTH - 40
    chart.height = 110
    chart.data = [timeline.counts]
    chart.categoryAxis.categoryNames = [
        _bucket_label(timeline, i) if i % every == 0 else "" for i in range(count)
    ]
    chart.categoryAxis.labels.fontName = "Helvetica"
    chart.categoryAxis.labels.fontSize = 7
    chart.categoryAxis.labels.boxAnchor = "n"
    chart.categoryAxis.strokeColor = GRID
    chart.categoryAxis.tickDown = 2
    chart.valueAxis.strokeColor = GRID
    chart.valueAxis.visibleGrid = True
    chart.valueAxis.gridStrokeColor = GRID
    chart.valueAxis.gridStrokeWidth = 0.25
    _value_axis(chart.valueAxis, max(timeline.counts))
    chart.bars[0].fillColor = ACCENT
    chart.bars[0].strokeColor = None
    chart.groupSpacing = 1 if count > 40 else 2
    drawing.add(chart)
    return drawing


def _describe_bucket(seconds: int) -> str:
    if seconds < 3600:
        return f"{seconds // 60}-minute"
    if seconds < 86400:
        return "hourly" if seconds == 3600 else f"{seconds // 3600}-hour"
    return "daily" if seconds == 86400 else "weekly"


def _timeline_section(data: ReportData) -> List[Flowable]:
    if data.is_empty:
        return []
    timeline = data.timeline
    busiest = max(range(len(timeline.counts)), key=lambda i: timeline.counts[i])
    return [
        _heading("Event timeline"),
        _timeline_chart(timeline),
        Paragraph(
            _text(
                f"Events per {_describe_bucket(timeline.bucket_seconds)} bucket, times in "
                f"the report's timezone. Busiest bucket: "
                f"{timeline.starts[busiest].strftime('%Y-%m-%d %H:%M')} "
                f"({timeline.counts[busiest]} events)."
            ),
            STYLES["note"],
        ),
    ]


def build_story(data: ReportData) -> List[Flowable]:
    """Every section of the report, in order, as reportlab flowables."""
    story: List[Flowable] = []
    # (a section's heading always stays on the same page as what follows it)
    for section in (_title_section, _summary_section, _types_section, _timeline_section):
        flowables = section(data)
        if flowables:
            story.append(KeepTogether(flowables[:2]))
        story.extend(flowables[2:])
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
