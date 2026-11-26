"""SIEM and syslog forwarding for NetSentry's detected events.

Every event the engine writes to the database can be forwarded to external
systems -- Splunk, Elastic, Wazuh, Graylog or any syslog collector -- as RFC
5424 syslog, CEF or JSON, over UDP, TCP, TLS or into a local file a log
shipper tails. See README.md "SIEM and Syslog Forwarding".

The pieces, in the order an event passes through them:

- normalize.py turns an Event into one flat dict with a stable field set,
  shared by every format
- sanitize.py and severity.py are the helpers the formats build on
- rfc5424.py, cef.py and json_format.py render that dict as bytes
- transports.py and file_output.py deliver the bytes
- sender.py queues them per destination and retries in the background
- dispatcher.py ties it together for the engine, the CLI and the dashboard
"""
