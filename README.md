# Malicious URL Post-Click Alert Case Planner

Lean copy of the GeoEdge monitoring workflow that concentrates on building Salesforce case plans from the GeoEdge history API. The script fetches alerts for `1d148bdbb9e6b86b977fcb6a5d69f83a`, hydrates them with advertiser metadata from `trc.geo_edge_*`, and emits the grouped data needed for automation.

## Capabilities
- Calls the GeoEdge v3 history API with automatic pagination and retry safeguards.
- Enriches alerts with advertiser/campaign details from MySQL so cases can reference account ids.
- Implements the latest grouping policy:
	- One case per advertiser for **Malicious Cloaking** (trigger keyword match), bundling every cloaking alert plus a summary of any additional trigger types tied to that advertiser.
	- One bulk case per remaining trigger detail, excluding advertisers that already have Malicious Cloaking so they are not double-counted.
- Outputs either a readable table or JSON, making it easy to plug the data into downstream automation.

## Project Layout
```
malicious_cloaking_alerts/
├── .env.example          # Template for GeoEdge + DB secrets
├── config.py             # Static defaults (alert id, log file, lookback window)
├── main.py               # Fetch + enrich + grouping pipeline
├── case_creator.py       # Salesforce case creation (optional)
├── requirements.txt      # Minimal dependencies
└── README.md             # This document
```

## Prerequisites
- Python 3.10+
- GeoEdge API key with `alerts/history` access
- Reachable MySQL instance that hosts the `trc.geo_edge_*` tables used for enrichment

## Setup
```bash
cd malicious_cloaking_alerts
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
cp .env.example .env
# Fill in GeoEdge + MySQL credentials
```

## Running
```bash
python main.py --hours 24            # human-readable summary
python main.py --hours 12 --json     # machine-readable payload
python main.py --hours 24 --trigger-summary
python main.py --hours 24 --only-trigger "Malicious URL Post-Click"
```

The script writes concise progress logs to `malicious_cloaking_alerts.log` and exits non-zero on failure so it can be wired into schedulers safely.

### Output Notes
- `malicious_cloaking_cases`: array of per-account payloads (account metadata, every cloaking alert, and a set of non-cloaking triggers observed on that account).
- `bulk_trigger_cases`: array of per-trigger payloads for the remaining alerts (each entry lists the affected accounts plus all matching alerts).
- Aggregate counters (`total_alerts`, `total_accounts`, etc.) are included to simplify monitoring.

## Configuration Tips
- Override `GEOEDGE_ALERT_ID`, `GEOEDGE_TRIGGER_TYPE_ID`, or `GEOEDGE_TRIGGER_NAME` in `.env` to point at different GeoEdge definitions.
- `ALERT_LOOKBACK_HOURS` in `config.py` controls the default window when `--hours` is omitted.

## Scheduling
Run it however you prefer (cron, Airflow, etc.). Example cron entry for a run every morning at 08:00 UTC:
```
0 8 * * * /path/to/.venv/bin/python /path/to/malicious_cloaking_alerts/main.py >> /var/log/mc_case_plan.log 2>&1
```

## Extending
- Feed the JSON output straight into Salesforce automation or a queue worker.
- Add CSV/Excel exporters or notification hooks if needed—keeping those concerns out of this core API-focused repo keeps the maintenance burden low.
# SF_Case
