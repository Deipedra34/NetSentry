"""PDF summary reports of the events NetSentry has detected.

Split into the same layers as the rest of the codebase:

  - data.py: report periods, plus read-only queries that turn the events,
    blocked_ips and threat_intel_cache tables into plain report data --
    no reportlab involved, so it's easy to test against a seeded database
  - pdf.py: lays that data out as a PDF with reportlab (tables plus charts
    from reportlab's own graphics module)
  - scheduler.py: generates the daily/weekly reports when they're due and
    rotates old ones

On-demand reports come from main.py (--report) and the dashboard's
/api/report endpoint; scheduled ones from ReportScheduler, which the
detection engine calls once per packet like AutoBlocker's expiry check.
"""
