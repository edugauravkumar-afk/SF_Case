import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from main import (
    TRIGGER_CATEGORY_NAME,
    build_case_plan,
    enrich_alerts_with_account_info,
    filter_trigger_category,
)


def main() -> None:
    load_dotenv('/Users/gaurav.k/Desktop/malicious_cloaking_alerts/.env')
    api_key = os.getenv('GEOEDGE_API_KEY', '').strip()
    if not api_key:
        raise SystemExit('Missing GEOEDGE_API_KEY')

    base_url = 'https://api.geoedge.com/rest/analytics/v3/alerts/history'
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=24)
    end = now

    limit = 1000
    offset = 0
    all_alerts: list[dict] = []

    while True:
        params = {
            'alert_id': os.getenv('GEOEDGE_ALERT_ID', '1d148bdbb9e6b86b977fcb6a5d69f83a'),
            'full_raw': 1,
            'limit': limit,
            'offset': offset,
            'min_datetime': start.strftime('%Y-%m-%d %H:%M:%S'),
            'max_datetime': end.strftime('%Y-%m-%d %H:%M:%S'),
        }
        resp = requests.get(base_url, headers={'Authorization': api_key}, params=params, timeout=120)
        resp.raise_for_status()
        payload = resp.json()
        page = payload.get('alerts') or payload.get('response', {}).get('alerts') or []
        if not page:
            break
        for alert in page:
            alert.setdefault('trigger_type_name', TRIGGER_CATEGORY_NAME)
        all_alerts.extend(page)
        if len(page) < limit:
            break
        offset += limit

    print('window', start.isoformat(), 'to', end.isoformat())
    print('total_alerts_fetched', len(all_alerts))

    if not all_alerts:
        print('no alerts in window')
        return

    enriched = enrich_alerts_with_account_info(all_alerts)
    filtered = filter_trigger_category(enriched, TRIGGER_CATEGORY_NAME)
    plan = build_case_plan(filtered)

    mc = len(plan.get('malicious_cloaking_cases', []))
    bulk = len(plan.get('bulk_trigger_cases', []))
    print('malicious_cloaking_cases', mc)
    print('bulk_trigger_cases', bulk)
    print('total_cases', mc + bulk)


if __name__ == '__main__':
    main()
