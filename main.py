#!/usr/bin/env python3
"""GeoEdge Malicious Cloaking alert case planner."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Sequence

import pymysql
import requests
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import (
    ALERT_LOOKBACK_HOURS,
    GEOEDGE_SETTINGS,
    LOG_FILE,
    PROJECT_NAME,
    TRIGGER_CATEGORY_NAME,
    TRIGGER_TYPE_OVERRIDES,
)

load_dotenv()
LOG_FILE_PATH = str(LOG_FILE)


def log_message(message: str) -> None:
    """Log a timestamped message to stdout and the local log file."""

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    entry = f"[{timestamp}] {message}"
    print(entry)
    try:
        with open(LOG_FILE_PATH, "a", encoding="utf-8") as handle:
            handle.write(entry + "\n")
    except OSError:
        pass


def _fetch_trigger_type_map(session: requests.Session, api_key: str) -> Dict[str, str]:
    url = "https://api.geoedge.com/rest/analytics/v3/alerts/trigger-types"
    headers = {"Authorization": api_key}
    try:
        response = session.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:  # pragma: no cover - best effort
        log_message(f"⚠️ Failed to fetch trigger types: {exc}")
        return {}

    mapping: Dict[str, str] = {}
    for entry in payload.get("trigger-types", []):
        trigger_id = str(entry.get("id", "")).strip()
        if not trigger_id:
            continue
        description = (entry.get("description") or entry.get("key") or "").strip()
        if description:
            mapping[trigger_id] = description
    return mapping


def _env_or_fail(key: str) -> str:
    value = os.getenv(key, "").strip()
    if not value:
        raise RuntimeError(f"Missing environment variable: {key}")
    return value


def _get_alert_id() -> str:
    return os.getenv("GEOEDGE_ALERT_ID", GEOEDGE_SETTINGS["alert_id"]).strip()


def _get_trigger_type_id() -> str | None:
    env_value = os.getenv("GEOEDGE_TRIGGER_TYPE_ID", "").strip()
    if env_value:
        return env_value
    return GEOEDGE_SETTINGS.get("trigger_type_id")


def _get_trigger_name() -> str:
    return os.getenv("GEOEDGE_TRIGGER_NAME", GEOEDGE_SETTINGS["trigger_name"]).strip() or TRIGGER_CATEGORY_NAME


def get_database_connection() -> pymysql.connections.Connection:
    host = _env_or_fail("MYSQL_HOST")
    port = int(os.getenv("MYSQL_PORT", "6033"))
    user = _env_or_fail("MYSQL_USER")
    password = _env_or_fail("MYSQL_PASSWORD")
    database = _env_or_fail("MYSQL_DB")

    return pymysql.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=database,
        cursorclass=pymysql.cursors.DictCursor,
    )


def fetch_malicious_cloaking_alerts(
    *,
    lookback_hours: int | None = None,
    page_size: int | None = None,
) -> List[Dict[str, Any]]:
    """Call the GeoEdge API, paginate, and return alerts for the configured alert id."""

    api_key = _env_or_fail("GEOEDGE_API_KEY")
    base_url = GEOEDGE_SETTINGS["base_url"]
    trigger_name = _get_trigger_name()

    default_page_limit = page_size or int(os.getenv("GEOEDGE_PAGE_LIMIT", "1500"))
    min_page_limit = max(200, int(os.getenv("GEOEDGE_MIN_PAGE_LIMIT", "300")))

    params: Dict[str, Any] = {
        "alert_id": _get_alert_id(),
        "full_raw": 1,
        "limit": default_page_limit,
    }

    if lookback_hours is not None:
        now = datetime.now(timezone.utc)
        from_time = now - timedelta(hours=lookback_hours)
        params["min_datetime"] = from_time.strftime("%Y-%m-%d %H:%M:%S")
        params["max_datetime"] = now.strftime("%Y-%m-%d %H:%M:%S")

    trigger_type_id = _get_trigger_type_id()
    if trigger_type_id:
        params["trigger_type_id"] = trigger_type_id

    headers = {"Authorization": api_key, "Content-Type": "application/json"}

    session = requests.Session()
    retry_config = Retry(
        total=3,
        read=3,
        connect=3,
        status_forcelist=[429, 500, 502, 503, 504],
        backoff_factor=1.5,
        allowed_methods=["GET"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry_config)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    trigger_type_map: Dict[str, str] = {**TRIGGER_TYPE_OVERRIDES}
    try:
        trigger_type_map.update(_fetch_trigger_type_map(session, api_key))
    except Exception:
        pass

    log_message(f"Fetching GeoEdge alerts for {trigger_name}")
    log_message(f"GeoEdge request parameters: {params}")

    all_alerts: List[Dict[str, Any]] = []
    offset = 0
    total_fetched = 0
    max_retries = 5
    base_timeout = 120

    while True:
        params["offset"] = offset
        current_limit = params["limit"]
        response = None
        last_error = None

        for attempt in range(max_retries):
            try:
                timeout = base_timeout + (attempt * 30)
                log_message(f"Fetching page (offset={offset}, limit={current_limit}) - Attempt {attempt + 1}/{max_retries}")
                response = session.get(base_url, headers=headers, params=params, timeout=timeout)
                if response.status_code == 200:
                    break
                if response.status_code >= 500:
                    last_error = f"Server error {response.status_code}"
                    log_message(f"⚠️ {last_error}, retrying...")
                    time.sleep(10 * (attempt + 1))
                else:
                    break
            except requests.exceptions.Timeout:
                last_error = f"Timeout after {timeout}s"
                log_message(f"⚠️ {last_error}")
                if attempt < max_retries - 1:
                    time.sleep(30 * (attempt + 1))
            except requests.exceptions.ConnectionError as exc:
                last_error = f"Connection error: {exc}"
                log_message(f"⚠️ {last_error}")
                if attempt < max_retries - 1:
                    time.sleep(30 * (attempt + 1))
            except requests.RequestException as exc:
                last_error = str(exc)
                log_message(f"⚠️ Request failed: {last_error}")
                if attempt < max_retries - 1:
                    time.sleep(30 * (attempt + 1))

        if response is None:
            if current_limit > min_page_limit:
                new_limit = max(min_page_limit, current_limit // 2)
                params["limit"] = new_limit
                log_message(
                    f"Reducing page size from {current_limit} to {new_limit} due to repeated failures; retrying same offset"
                )
                continue
            raise RuntimeError(f"GeoEdge API request failed after {max_retries} attempts: {last_error}")

        if response.status_code != 200:
            if response.status_code >= 500 and current_limit > min_page_limit:
                new_limit = max(min_page_limit, current_limit // 2)
                params["limit"] = new_limit
                log_message(
                    f"Server error {response.status_code}; reducing page size to {new_limit} and retrying offset {offset}"
                )
                continue
            raise RuntimeError(f"GeoEdge API returned {response.status_code}: {response.text}")

        payload = response.json()
        page_alerts: List[Dict[str, Any]] = []
        if isinstance(payload, dict):
            if isinstance(payload.get("alerts"), list):
                page_alerts = payload["alerts"]
            elif isinstance(payload.get("response"), dict) and isinstance(payload["response"].get("alerts"), list):
                page_alerts = payload["response"]["alerts"]

        if not page_alerts:
            log_message(f"No more alerts at offset {offset}")
            break

        total_fetched += len(page_alerts)
        for alert in page_alerts:
            alert.setdefault("trigger_type_name", trigger_name)
            if not alert.get("trigger_metadata") and alert.get("trigger_type_id"):
                mapped = trigger_type_map.get(str(alert.get("trigger_type_id")))
                if mapped:
                    alert["trigger_metadata"] = mapped
        all_alerts.extend(page_alerts)

        if current_limit < default_page_limit and len(page_alerts) == current_limit:
            new_limit = min(default_page_limit, current_limit * 2)
            if new_limit != current_limit:
                params["limit"] = new_limit
                log_message(f"Increasing page size to {new_limit} after stable responses")

        if len(page_alerts) < current_limit:
            log_message(f"Last page reached (got {len(page_alerts)} < {current_limit})")
            break

        offset += current_limit
        if offset > 50000:
            log_message(f"Safety limit reached at offset {offset}")
            break

    log_message(f"Total: Fetched {total_fetched} alerts")
    session.close()
    return all_alerts


def enrich_alerts_with_account_info(alerts: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Attach advertiser/campaign metadata for each GeoEdge alert."""

    filtered_alerts: List[Dict[str, Any]] = []

    for alert in alerts:
        project_info = alert.get("project_name") or {}
        if not project_info:
            continue

        project_ids = list(project_info.keys())
        if not project_ids:
            continue

        project_id = project_ids[0]
        location_block = alert.get("location") or {}
        if location_block:
            code, name = next(iter(location_block.items()))
        else:
            code, name = "Unknown", "Unknown"
        enriched = dict(alert)
        enriched.update(
            {
                "location_code": code,
                "location_name": name,
                "project_id": project_id,
                "project_name_str": project_info[project_id],
            }
        )
        filtered_alerts.append(enriched)

    if not filtered_alerts:
        log_message("No alerts contained project metadata")
        return []

    unique_project_ids = sorted({alert["project_id"] for alert in filtered_alerts})
    log_message(f"Querying publisher metadata for {len(unique_project_ids)} project ids")

    project_data: Dict[str, List[Dict[str, Any]]] = {}
    connection = None
    try:
        connection = get_database_connection()
        with connection.cursor() as cursor:
            project_placeholders = ",".join(["%s"] * len(unique_project_ids))
            sql = (
                "SELECT DISTINCT "
                "p.project_id, "
                "p.campaign_id, "
                "lp.advertiser_id AS account_id, "
                "pub.name AS account_name, "
                "pub.country AS publisher_country "
                "FROM trc.geo_edge_projects p "
                "JOIN trc.geo_edge_landing_pages lp ON p.campaign_id = lp.campaign_id "
                "JOIN trc.publishers pub ON lp.advertiser_id = pub.id "
                f"WHERE p.project_id IN ({project_placeholders})"
            )
            cursor.execute(sql, unique_project_ids)
            rows = cursor.fetchall()
            for row in rows:
                project_data.setdefault(row["project_id"], []).append(row)
    except pymysql.MySQLError as exc:
        raise RuntimeError(f"Database query failed: {exc}") from exc
    finally:
        if connection:
            try:
                connection.close()
            except Exception:
                pass

    log_message(f"Found account data for {len(project_data)} projects")

    enriched_alerts: List[Dict[str, Any]] = []
    for alert in filtered_alerts:
        project_id = alert["project_id"]
        project_rows = project_data.get(project_id, [])

        if not project_rows:
            fallback = dict(alert)
            fallback.update(
                {
                    "campaign_id": "Unknown",
                    "account_id": "Unknown",
                    "account_name": "Unknown",
                    "publisher_country": "Unknown",
                }
            )
            enriched_alerts.append(fallback)
            continue

        for row in project_rows:
            enriched = dict(alert)
            enriched.update(
                {
                    "campaign_id": row["campaign_id"],
                    "account_id": row["account_id"],
                    "account_name": row.get("account_name", "Unknown"),
                    "publisher_country": row.get("publisher_country", "Unknown"),
                }
            )
            enriched_alerts.append(enriched)

    log_message(f"Enriched {len(enriched_alerts)} alerts with account info")
    return enriched_alerts


def filter_trigger_category(alerts: List[Dict[str, Any]], category_name: str) -> List[Dict[str, Any]]:
    category_lower = category_name.strip().lower()
    filtered = [
        alert
        for alert in alerts
        if alert.get("trigger_type_name", "").strip().lower() == category_lower
        or alert.get("trigger_metadata", "").strip().lower() == category_lower
    ]
    log_message(f"Filtered to {len(filtered)} '{category_name}' alerts (from {len(alerts)} total)")
    return filtered


def _normalize_trigger_detail(alert: Dict[str, Any]) -> str:
    detail = (alert.get("trigger_metadata") or alert.get("trigger_type_name") or "Unknown Trigger").strip()
    return detail or "Unknown Trigger"


def _is_malicious_cloaking(trigger_detail: str) -> bool:
    return trigger_detail.lower() == "malicious cloaking"


def _summarize_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    location_code = alert.get("location_code", "")
    location_name = alert.get("location_name", "")
    detection_location = f"{location_code} - {location_name}".strip(" -")
    return {
        "campaign_id": str(alert.get("campaign_id", "Unknown")),
        "trigger_metadata": alert.get("trigger_metadata", ""),
        "trigger_type_name": alert.get("trigger_type_name", ""),
        "trigger_type_id": alert.get("trigger_type_id", ""),
        "alert_name": alert.get("alert_name", ""),
        "event_datetime": alert.get("event_datetime", ""),
        "detection_location": detection_location,
        "alert_details_url": alert.get("alert_details_url", ""),
    }


def _init_account_case(alert: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "account_id": str(alert.get("account_id", "Unknown")),
        "account_name": alert.get("account_name", "Unknown"),
        "publisher_country": alert.get("publisher_country", "Unknown"),
        "campaign_ids": set(),
        "alerts": [],
    }


def _init_mc_case(alert: Dict[str, Any]) -> Dict[str, Any]:
    entry = _init_account_case(alert)
    entry["other_triggers"] = set()
    entry["other_activity"] = {}
    return entry


def build_case_plan(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    mc_cases: Dict[str, Dict[str, Any]] = {}
    bulk_cases: Dict[str, Dict[str, Any]] = {}

    for alert in alerts:
        account_id = str(alert.get("account_id", "Unknown"))
        trigger_detail = _normalize_trigger_detail(alert)
        alert_summary = _summarize_alert(alert)

        if _is_malicious_cloaking(trigger_detail):
            entry = mc_cases.setdefault(account_id, _init_mc_case(alert))
            entry["alerts"].append(alert_summary)
            entry["campaign_ids"].add(alert_summary["campaign_id"])
            continue

        if account_id in mc_cases:
            entry = mc_cases[account_id]
            entry["other_triggers"].add(trigger_detail)
            entry.setdefault("other_activity", {}).setdefault(trigger_detail, []).append(alert_summary)
            entry["campaign_ids"].add(alert_summary["campaign_id"])
            continue

        trigger_case = bulk_cases.setdefault(
            trigger_detail,
            {"trigger": trigger_detail, "accounts": {}},
        )
        account_entry = trigger_case["accounts"].setdefault(account_id, _init_account_case(alert))
        account_entry["alerts"].append(alert_summary)
        account_entry["campaign_ids"].add(alert_summary["campaign_id"])

    mc_case_list: List[Dict[str, Any]] = []
    for _, payload in sorted(mc_cases.items(), key=lambda item: item[0]):
        case_entry = {
            "account_id": payload["account_id"],
            "account_name": payload["account_name"],
            "publisher_country": payload["publisher_country"],
            "campaign_ids": sorted(payload["campaign_ids"]),
            "alert_count": len(payload["alerts"]),
            "alerts": payload["alerts"],
        }
        if payload["other_triggers"]:
            case_entry["other_triggers"] = sorted(payload["other_triggers"])
            case_entry["other_activity"] = [
                {"trigger": trigger, "alerts": alerts}
                for trigger, alerts in sorted(payload.get("other_activity", {}).items())
            ]
        mc_case_list.append(case_entry)

    bulk_case_list: List[Dict[str, Any]] = []
    for trigger, payload in sorted(bulk_cases.items()):
        accounts_payload: List[Dict[str, Any]] = []
        total_alerts = 0
        for _, account_data in sorted(payload["accounts"].items()):
            account_entry = {
                "account_id": account_data["account_id"],
                "account_name": account_data["account_name"],
                "publisher_country": account_data["publisher_country"],
                "campaign_ids": sorted(account_data["campaign_ids"]),
                "alert_count": len(account_data["alerts"]),
                "alerts": account_data["alerts"],
            }
            accounts_payload.append(account_entry)
            total_alerts += account_entry["alert_count"]

        bulk_case_list.append(
            {
                "trigger": trigger,
                "account_count": len(accounts_payload),
                "alert_count": total_alerts,
                "accounts": accounts_payload,
            }
        )

    return {
        "project": PROJECT_NAME,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_alerts": len(alerts),
        "malicious_cloaking_accounts": len(mc_case_list),
        "bulk_case_count": len(bulk_case_list),
        "malicious_cloaking_cases": mc_case_list,
        "bulk_trigger_cases": bulk_case_list,
    }


def print_case_plan(plan: Dict[str, Any]) -> None:
    print()
    print(f"Case plan for {plan['project']} ({plan['generated_at']})")
    print(f"Total alerts considered: {plan['total_alerts']}")
    print(f"Malicious Cloaking accounts: {plan['malicious_cloaking_accounts']}")
    print(f"Bulk trigger cases: {plan['bulk_case_count']}")

    print("\nMalicious Cloaking Cases")
    if not plan["malicious_cloaking_cases"]:
        print("  None")
    else:
        for case in plan["malicious_cloaking_cases"]:
            print(f"- Account {case['account_id']} ({case['account_name']}) - {case['alert_count']} cloaking alerts")
            print(f"  Country: {case['publisher_country']}")
            print(f"  Campaign IDs: {', '.join(case['campaign_ids']) or 'N/A'}")
            if case.get("other_triggers"):
                print(f"  Other triggers: {', '.join(case['other_triggers'])}")
            for alert in case["alerts"]:
                print(
                    f"    · {alert['event_datetime']} | {alert['detection_location']} | {alert['trigger_metadata'] or alert['trigger_type_name']}"
                )
            if case.get("other_activity"):
                print("    Additional activity:")
                for extra in case["other_activity"]:
                    trigger = extra["trigger"]
                    for alert in extra["alerts"]:
                        print(
                            f"      - {trigger}: {alert['event_datetime']} | {alert['detection_location']}"
                        )

    print("\nBulk Trigger Cases")
    if not plan["bulk_trigger_cases"]:
        print("  None")
    else:
        for case in plan["bulk_trigger_cases"]:
            print(
                f"- Trigger '{case['trigger']}' → {case['account_count']} accounts / {case['alert_count']} alerts"
            )
            for account in case["accounts"]:
                print(
                    f"    · Account {account['account_id']} ({account['account_name']}), {account['alert_count']} alerts"
                )


def print_trigger_category_summary(plan: Dict[str, Any]) -> None:
    print("\nTrigger Category Summary (Accounts per Category)")
    if not plan["bulk_trigger_cases"]:
        print("  None")
        return
    for case in plan["bulk_trigger_cases"]:
        print(f"- {case['trigger']}: {case['account_count']} accounts")


def filter_case_plan_by_trigger(plan: Dict[str, Any], trigger_name: str) -> Dict[str, Any]:
    trigger_name = trigger_name.strip()
    filtered_bulk = [
        case for case in plan.get("bulk_trigger_cases", []) if case.get("trigger") == trigger_name
    ]
    total_alerts = sum(case.get("alert_count", 0) for case in filtered_bulk)
    return {
        **plan,
        "total_alerts": total_alerts,
        "malicious_cloaking_accounts": 0,
        "malicious_cloaking_cases": [],
        "bulk_case_count": len(filtered_bulk),
        "bulk_trigger_cases": filtered_bulk,
    }


def _parse_cli_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Malicious Cloaking alert case planner")
    parser.add_argument(
        "--hours",
        type=int,
        default=None,
        help="Limit alerts to the last N hours (default uses ALERT_LOOKBACK_HOURS).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the case plan as JSON for downstream automation.",
    )
    parser.add_argument(
        "--trigger-summary",
        action="store_true",
        help="Print accounts-per-trigger-category summary.",
    )
    parser.add_argument(
        "--only-trigger",
        help="Limit output to a single trigger category (e.g. 'Malicious URL Post-Click').",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None:
    args = _parse_cli_args(argv)
    lookback = args.hours if args.hours is not None else ALERT_LOOKBACK_HOURS

    log_message(f"Starting {PROJECT_NAME} (lookback={lookback}h)")
    alerts = fetch_malicious_cloaking_alerts(lookback_hours=lookback)

    if not alerts:
        log_message("GeoEdge returned no alerts for the requested window")
        print("No alerts found for the requested window.")
        return

    enriched_alerts = enrich_alerts_with_account_info(alerts)
    if not enriched_alerts:
        print("No alerts could be enriched with account metadata.")
        return

    filtered_alerts = filter_trigger_category(enriched_alerts, TRIGGER_CATEGORY_NAME)
    if not filtered_alerts:
        print(f"No alerts matched trigger category '{TRIGGER_CATEGORY_NAME}'.")
        return

    plan = build_case_plan(filtered_alerts)
    if args.only_trigger:
        plan = filter_case_plan_by_trigger(plan, args.only_trigger)

    if args.json:
        print(json.dumps(plan, indent=2))
    else:
        print_case_plan(plan)

    if args.trigger_summary:
        print_trigger_category_summary(plan)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        log_message(f"Run failed: {exc}")
        raise
