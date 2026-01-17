"""Configuration constants for the Malicious Cloaking alert case planner."""

from pathlib import Path

PROJECT_NAME = "Malicious Cloaking Alerts"
TRIGGER_CATEGORY_NAME = "Malicious URL Post-Click"
LOG_FILE = Path(__file__).with_name("malicious_cloaking_alerts.log")
ALERT_LOOKBACK_HOURS = 24

GEOEDGE_SETTINGS = {
    "base_url": "https://api.geoedge.com/rest/analytics/v3/alerts/history",
    "alert_id": "1d148bdbb9e6b86b977fcb6a5d69f83a",
    "trigger_name": TRIGGER_CATEGORY_NAME,
    "trigger_type_id": None,
}

TRIGGER_TYPE_OVERRIDES = {
    "72": "Back Button Hijack",
    "83": "Deceptive Site",
}
