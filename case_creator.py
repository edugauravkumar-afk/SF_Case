"""Salesforce case creator with Vertica/MySQL enrichment and rate-limit aware posting."""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Sequence

import mysql.connector
import requests
import vertica_python
from dotenv import load_dotenv
from mysql.connector.connection import MySQLConnection

# ---------------------------------------------------------------------------
# Environment & logging setup
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
LOGGER = logging.getLogger("case_creator")

# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------
def _env_or_default(key: str, default: str) -> str:
    value = os.getenv(key)
    if value is None:
        return default
    return value.strip()


def _env_or_fail(key: str) -> str:
    value = os.getenv(key)
    if value is None or not value.strip():
        raise RuntimeError(f"Missing required environment variable: {key}")
    return value.strip()


MYSQL_CFG = {
    "host": _env_or_default("MYSQL_HOST", "proxysql-office.taboolasyndication.com"),
    "port": int(_env_or_default("MYSQL_PORT", "6033")),
    "user": _env_or_default("MYSQL_USER", ""),
    "password": _env_or_default("MYSQL_PASSWORD", ""),
    "auth_plugin": _env_or_default("MYSQL_AUTH_PLUGIN", "mysql_clear_password"),
    "autocommit": True,
    "connection_timeout": int(_env_or_default("MYSQL_CONNECTION_TIMEOUT", "15")),
}

VERTICA_CFG = {
    "host": _env_or_default("VERTICA_HOST", "office-vrt.taboolasyndication.com"),
    "port": int(_env_or_default("VERTICA_PORT", "5433")),
    "user": _env_or_default("VERTICA_USER", ""),
    "password": _env_or_default("VERTICA_PASSWORD", ""),
    "autocommit": True,
}

SF_CASE_URL = _env_or_fail("SF_CASE_URL")
SF_API_TOKEN = _env_or_fail("SF_API_TOKEN")
GEOEDGE_API_KEY = _env_or_fail("GEOEDGE_API_KEY")
SF_OWNER_ID = _env_or_default("SF_OWNER_ID", "0050V000007mBZkQAM")

MAX_CASE_RETRIES = int(_env_or_default("CASE_MAX_RETRIES", "4"))
INITIAL_BACKOFF = float(_env_or_default("CASE_INITIAL_BACKOFF", "5"))
BATCH_SLEEP = float(_env_or_default("CASE_BATCH_SLEEP", "0"))
CASE_PLAN_PATH = Path(_env_or_default("CASE_PLAN_PATH", "latest_case_plan.json"))
BULK_MAX_ACCOUNTS_PER_CASE = int(_env_or_default("BULK_MAX_ACCOUNTS_PER_CASE", "5"))
BULK_MAX_CAMPAIGN_IDS_LEN = int(_env_or_default("BULK_MAX_CAMPAIGN_IDS_LEN", "240"))
DEBUG_CASE_PAYLOAD = _env_or_default("DEBUG_CASE_PAYLOAD", "0").lower() in {"1", "true", "yes"}
PROGRESS_FILE_DEFAULT = _env_or_default("CASE_PROGRESS_FILE", "case_creation_progress.jsonl")

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
class DatabaseClient:
    """Thin wrapper that keeps single open connections per backend."""

    def __init__(self) -> None:
        self._mysql: Optional[MySQLConnection] = None
        self._vertica = None

    def _ensure_mysql(self) -> MySQLConnection:
        if self._mysql is None or not self._mysql.is_connected():
            self._mysql = mysql.connector.connect(**MYSQL_CFG)
        return self._mysql

    def _ensure_vertica(self):
        if self._vertica is None:
            self._vertica = vertica_python.connect(**VERTICA_CFG)
        elif self._vertica.closed():
            self._vertica = vertica_python.connect(**VERTICA_CFG)
        return self._vertica

    def mysql_query(self, sql: str, params: Sequence[Any] = ()) -> List[tuple[Any, ...]]:
        conn = self._ensure_mysql()
        with conn.cursor() as cursor:  # type: ignore[arg-type]
            cursor.execute(sql, params)
            return list(cursor.fetchall())

    def vertica_query(self, sql: str, params: Sequence[Any] = ()) -> List[tuple[Any, ...]]:
        conn = self._ensure_vertica()
        cur = conn.cursor()
        try:
            cur.execute(sql, params)
            return list(cur.fetchall())
        finally:
            cur.close()

    def close(self) -> None:
        if self._mysql is not None:
            try:
                self._mysql.close()
            except Exception:  # pragma: no cover - best effort cleanup
                pass
        if self._vertica is not None:
            try:
                self._vertica.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Data fetchers
# ---------------------------------------------------------------------------
CORE_SQL = """
    SELECT
        pc.name,
        pc.email,
        camp.id AS campaign_id,
        items.id AS item_id,
        items.source_url AS url
    FROM apps_config.pc_users AS pc
    LEFT JOIN trc.sp_campaigns_latest_config AS camp
        ON pc.publisher_id = camp.syndicator_id
    LEFT JOIN trc.sp_campaign_inventory_instructions AS items
        ON items.campaign_id = camp.id
    WHERE pc.publisher_id = %s
    ORDER BY
        CASE
            WHEN camp.status = 'APPROVED' AND camp.display_status = 'RUNNING' THEN 1
            WHEN camp.status = 'APPROVED' THEN 2
            ELSE 3
        END,
        (
            (camp.id IS NULL)::int +
            (camp.status IS NULL)::int +
            (camp.display_status IS NULL)::int +
            (camp.start_date IS NULL)::int +
            (items.id IS NULL)::int +
            (items.source_url IS NULL)::int
        ) ASC
    LIMIT 1
"""


SPEND_SQL = """
    SELECT SUM(spent)
    FROM reports.sp_campaigns_report_daily_v2
    WHERE publisher_id = %s
    GROUP BY publisher_id
"""


class CaseDataAccessor:
    def __init__(self, db: DatabaseClient) -> None:
        self._db = db
        self._http_session = requests.Session()
        self._http_session.headers.update({"Authorization": GEOEDGE_API_KEY})

    def is_tier3(self, publisher_id: int) -> bool:
        rows = self._db.vertica_query(
            "SELECT media_tier_id FROM trc.sp_syndication_base WHERE syndicator_id = %s LIMIT 1",
            (publisher_id,),
        )
        return bool(rows) and rows[0][0] == 3

    def fetch_core(self, publisher_id: int) -> dict[str, Any]:
        rows = self._db.vertica_query(CORE_SQL, (publisher_id,))
        if not rows:
            return {}
        name, email, campaign_id, item_id, url = rows[0]
        return {
            "name": name,
            "email": email,
            "campaign_id": campaign_id,
            "item_id": item_id,
            "url": url,
        }

    def fetch_projects(self, campaign_id: Optional[int]) -> tuple[str, List[str]]:
        if campaign_id is None:
            return "No", []
        rows = self._db.mysql_query(
            "SELECT project_id FROM trc.geo_edge_projects WHERE campaign_id = %s",
            (campaign_id,),
        )
        project_ids = [row[0] for row in rows]
        return ("Yes" if project_ids else "No"), project_ids

    def alerts_exist(self, project_ids: Sequence[str]) -> str:
        if not project_ids:
            return "No"
        base_url = "https://api.geoedge.com/rest/analytics/v3/alerts/history"
        params = {"limit": 1}
        for pid in project_ids:
            params["project_id"] = pid
            resp = self._http_session.get(base_url, params=params, timeout=20)
            resp.raise_for_status()
            body = resp.json()
            alerts = body.get("response", {}).get("alerts") or body.get("alerts", [])
            if alerts:
                return "Yes"
        return "No"

    def total_spent(self, publisher_id: int) -> Optional[float]:
        rows = self._db.vertica_query(SPEND_SQL, (publisher_id,))
        return rows[0][0] if rows else None


# ---------------------------------------------------------------------------
# Case plan loader (from main.py output)
# ---------------------------------------------------------------------------
class CasePlanIndex:
    @staticmethod
    def _has_cloaking_alerts(alerts: Sequence[dict[str, Any]]) -> bool:
        for alert in alerts:
            candidate = (
                (alert.get("trigger_metadata") or "").strip()
                or (alert.get("alert_name") or "").strip()
                or ""
            )
            if "cloaking" in candidate.lower():
                return True
        return False

    def __init__(self, plan_path: Optional[Path]) -> None:
        self._plan_path = plan_path
        self._accounts: dict[str, dict[str, Any]] = {}
        self._bulk_triggers: dict[str, dict[str, Any]] = {}
        self._account_triggers: dict[str, set[str]] = {}
        self._account_trigger_alerts: dict[str, dict[str, list[dict[str, Any]]]] = {}
        self._mc_account_ids: list[int] = []
        if plan_path is not None:
            self._load(plan_path)

    def _load(self, plan_path: Path) -> None:
        if not plan_path.exists():
            LOGGER.warning("Case plan file not found: %s", plan_path)
            return
        try:
            raw = plan_path.read_text(encoding="utf-8")
        except OSError as exc:
            LOGGER.warning("Unable to read case plan %s: %s", plan_path, exc)
            return
        marker = "\"project\""
        marker_pos = raw.find(marker)
        if marker_pos == -1:
            LOGGER.warning("Case plan %s does not contain expected JSON keys", plan_path)
            return
        start = raw.rfind("{", 0, marker_pos)
        if start == -1:
            LOGGER.warning("Case plan %s does not contain a JSON object", plan_path)
            return
        try:
            plan = json.loads(raw[start:])
        except json.JSONDecodeError as exc:
            LOGGER.warning("Unable to parse case plan JSON %s: %s", plan_path, exc)
            return
        self._index_plan(plan)

    def _index_plan(self, plan: dict[str, Any]) -> None:
        accounts: dict[str, dict[str, Any]] = {}
        bulk_triggers: dict[str, dict[str, Any]] = {}
        account_triggers: dict[str, set[str]] = {}
        account_trigger_alerts: dict[str, dict[str, list[dict[str, Any]]]] = {}
        mc_account_ids: list[int] = []
        for case in plan.get("malicious_cloaking_cases", []):
            account_id = str(case.get("account_id"))
            accounts[account_id] = case
            alerts = case.get("alerts", []) or []
            if self._has_cloaking_alerts(alerts):
                try:
                    mc_account_ids.append(int(account_id))
                except (TypeError, ValueError):
                    continue
        for trigger_case in plan.get("bulk_trigger_cases", []):
            trigger_name = str(trigger_case.get("trigger", "")).strip()
            if trigger_name:
                bulk_triggers[trigger_name] = trigger_case
            for account in trigger_case.get("accounts", []):
                account_id = str(account.get("account_id"))
                if trigger_name:
                    account_triggers.setdefault(account_id, set()).add(trigger_name)
                    account_trigger_alerts.setdefault(account_id, {}).setdefault(
                        trigger_name, account.get("alerts", []) or []
                    )
                existing = accounts.get(account_id)
                if existing and self._has_cloaking_alerts(existing.get("alerts", []) or []):
                    continue
                accounts[account_id] = account
        self._accounts = accounts
        self._bulk_triggers = bulk_triggers
        self._account_triggers = account_triggers
        self._account_trigger_alerts = account_trigger_alerts
        self._mc_account_ids = sorted(set(mc_account_ids))
        LOGGER.info("Loaded %s accounts from case plan", len(self._accounts))

    def get_account(self, publisher_id: int) -> Optional[dict[str, Any]]:
        if not self._accounts:
            return None
        return self._accounts.get(str(publisher_id))

    def get_bulk_trigger(self, trigger_name: str) -> Optional[dict[str, Any]]:
        if not self._bulk_triggers:
            return None
        return self._bulk_triggers.get(trigger_name)

    def get_account_triggers(self, publisher_id: int) -> list[str]:
        if not self._account_triggers:
            return []
        return sorted(self._account_triggers.get(str(publisher_id), set()))

    def get_account_trigger_alerts(self, publisher_id: int, trigger_name: str) -> list[dict[str, Any]]:
        if not self._account_trigger_alerts:
            return []
        return list(self._account_trigger_alerts.get(str(publisher_id), {}).get(trigger_name, []))

    def list_bulk_triggers(self) -> list[str]:
        return sorted(self._bulk_triggers.keys())

    def list_account_ids(self) -> list[int]:
        ids: list[int] = []
        for key in self._accounts.keys():
            try:
                ids.append(int(str(key)))
            except (TypeError, ValueError):
                continue
        return sorted(set(ids))

    def list_malicious_account_ids(self) -> list[int]:
        return list(self._mc_account_ids)

    def is_malicious_account_id(self, publisher_id: int) -> bool:
        return publisher_id in set(self._mc_account_ids)


# ---------------------------------------------------------------------------
# Case payload + posting
# ---------------------------------------------------------------------------
@dataclass
class CasePayload:
    publisher_id: int
    payload: dict[str, Any]


@dataclass
class CaseResult:
    publisher_id: int
    success: bool
    response: Optional[dict[str, Any]] = None
    error: Optional[str] = None


class ProgressTracker:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._seen: dict[str, bool] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            with self._path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    key = entry.get("key")
                    if key:
                        self._seen[str(key)] = bool(entry.get("success"))
        except OSError:
            return

    def has(self, key: str) -> bool:
        return bool(self._seen.get(key))

    def record(self, key: str, result: CaseResult) -> None:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "key": key,
            "publisher_id": result.publisher_id,
            "success": result.success,
            "error": result.error,
        }
        try:
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
        except OSError:
            return
        self._seen[key] = result.success


class CaseBuilder:
    def __init__(self, accessor: CaseDataAccessor, plan_index: Optional[CasePlanIndex] = None) -> None:
        self._accessor = accessor
        self._plan_index = plan_index

    @staticmethod
    def _has_cloaking_alerts(alerts: Sequence[dict[str, Any]]) -> bool:
        for alert in alerts:
            candidate = (
                (alert.get("trigger_metadata") or "").strip()
                or (alert.get("alert_name") or "").strip()
                or ""
            )
            if "cloaking" in candidate.lower():
                return True
        return False

    @staticmethod
    def _render_pipe_table(headers: list[str], rows: list[list[str]]) -> list[str]:
        lines = [" | ".join(headers), " | ".join(["---"] * len(headers))]
        for row in rows:
            lines.append(" | ".join(row))
        return lines

    @staticmethod
    def _collect_campaign_ids(accounts: Sequence[dict[str, Any]]) -> list[str]:
        ids: list[str] = []
        seen = set()
        for acct in accounts:
            for cid in acct.get("campaign_ids", []) or []:
                cid_str = str(cid)
                if cid_str and cid_str not in seen:
                    seen.add(cid_str)
                    ids.append(cid_str)
        return ids

    def _build_bulk_payload(
        self,
        trigger_name: str,
        accounts: Sequence[dict[str, Any]],
        part_label: Optional[str] = None,
    ) -> CasePayload:
        # Use first account as primary for required Salesforce fields
        primary = accounts[0]
        publisher_id = int(primary.get("account_id"))

        campaign_ids = self._collect_campaign_ids(accounts)
        campaign_ids_str = ", ".join(campaign_ids) if campaign_ids else "Unknown"
        trigger_detail = trigger_name

        description_lines = [
            "Malicious URL Post-Click Alerts",
            f"Trigger: {trigger_name}",
        ]
        if part_label:
            description_lines.append(f"Batch: {part_label}")
        description_lines.append("")
        description_lines.append("Accounts:")

        entry_lines: list[str] = []
        for idx, acct in enumerate(accounts, start=1):
            account_id = str(acct.get("account_id", "Unknown"))
            account_name = str(acct.get("account_name") or "Unknown")

            latest_per_campaign: dict[str, dict[str, Any]] = {}
            for alert in acct.get("alerts", []) or []:
                campaign_key = str(alert.get("campaign_id", "Unknown"))
                parsed_dt = self._parse_event_dt(alert.get("event_datetime"))
                current = latest_per_campaign.get(campaign_key)
                if current is None or parsed_dt > current["dt"]:
                    latest_per_campaign[campaign_key] = {
                        "dt": parsed_dt,
                        "url": alert.get("alert_details_url", ""),
                    }

            entry_lines.append(f"{idx}. Account ID: {account_id}")
            entry_lines.append(f"   Name:       {account_name}")
            if self._plan_index:
                triggers = self._plan_index.get_account_triggers(int(account_id))
                other_triggers = [t for t in triggers if t and t != trigger_name]
                if other_triggers:
                    entry_lines.append(f"   Other Triggers: {', '.join(other_triggers)}")
                    for other_trigger in other_triggers:
                        alerts = self._plan_index.get_account_trigger_alerts(int(account_id), other_trigger)
                        other_latest_per_campaign: dict[str, str] = {}
                        for alert in alerts:
                            campaign_id = str(alert.get("campaign_id", "Unknown"))
                            url = alert.get("alert_details_url") or "Unavailable"
                            if campaign_id not in other_latest_per_campaign:
                                other_latest_per_campaign[campaign_id] = url
                        if not other_latest_per_campaign:
                            entry_lines.append(f"   Alerts ({other_trigger}):")
                            entry_lines.append("     • No alert URLs captured")
                            continue
                        entry_lines.append(f"   Alerts ({other_trigger}):")
                        for cid in sorted(other_latest_per_campaign):
                            entry_lines.append(
                                f"     • Campaign {cid}: {other_latest_per_campaign[cid]}"
                            )

            if not latest_per_campaign:
                entry_lines.append("   Campaign:   Unknown")
                entry_lines.append("   Alert URL:  Unavailable")
                entry_lines.append("")
                continue

            entry_lines.append(f"   Alerts ({trigger_name}):")
            for cid in sorted(latest_per_campaign):
                url = latest_per_campaign[cid]["url"] or "Unavailable"
                entry_lines.append(f"     - Campaign {cid}: {url}")
            entry_lines.append("")

        if entry_lines and entry_lines[-1] == "":
            entry_lines.pop()
        description_lines.extend(entry_lines)

        subject = trigger_name
        if part_label:
            subject = f"{subject} ({part_label})"

        payload = {
            "record_type": "0123o00000224fEAAQ",
            "case_type": "Fraud",
            "request_for": trigger_detail,
            "backstage_account_id": str(publisher_id),
            "flag_origin": "GeoEdge",
            "subject": subject,
            "description": "\n".join(description_lines),
            "status": "New",
            "case_origin": "R&D Alert",
            "campaign_ids": campaign_ids_str,
            "ge_detected": "Yes",
            "ge_scanned": "Yes",
        }
        if SF_OWNER_ID:
            payload["owner_id"] = SF_OWNER_ID
        return CasePayload(publisher_id=publisher_id, payload=payload)

    def build_bulk_trigger_cases(
        self,
        trigger_name: str,
        max_accounts: Optional[int] = None,
        max_accounts_per_case: Optional[int] = None,
        max_campaign_ids_len: Optional[int] = None,
    ) -> list[CasePayload]:
        if not self._plan_index:
            raise ValueError("Bulk trigger cases require a case plan index")
        trigger_case = self._plan_index.get_bulk_trigger(trigger_name)
        if not trigger_case:
            return []

        accounts = trigger_case.get("accounts", []) or []
        if not accounts:
            return []
        if max_accounts is not None:
            accounts = accounts[:max_accounts]

        per_case_limit = max_accounts_per_case or BULK_MAX_ACCOUNTS_PER_CASE
        campaign_len_limit = max_campaign_ids_len or BULK_MAX_CAMPAIGN_IDS_LEN

        batches: list[list[dict[str, Any]]] = []
        current_accounts: list[dict[str, Any]] = []
        current_campaign_ids: list[str] = []

        for acct in accounts:
            next_accounts = current_accounts + [acct]
            next_campaign_ids = self._collect_campaign_ids(next_accounts)
            next_campaign_len = len(", ".join(next_campaign_ids)) if next_campaign_ids else 0

            too_many_accounts = per_case_limit and len(next_accounts) > per_case_limit
            too_long_campaigns = campaign_len_limit and next_campaign_len > campaign_len_limit

            if (too_many_accounts or too_long_campaigns) and current_accounts:
                batches.append(current_accounts)
                current_accounts = [acct]
                current_campaign_ids = self._collect_campaign_ids(current_accounts)
                continue

            current_accounts = next_accounts
            current_campaign_ids = next_campaign_ids

        if current_accounts:
            batches.append(current_accounts)

        total = len(batches)
        payloads: list[CasePayload] = []
        for idx, batch in enumerate(batches, start=1):
            part_label = f"{idx}/{total}" if total > 1 else None
            payloads.append(self._build_bulk_payload(trigger_name, batch, part_label=part_label))
        return payloads

    def build_bulk_trigger_case(self, trigger_name: str, max_accounts: Optional[int] = None) -> Optional[CasePayload]:
        payloads = self.build_bulk_trigger_cases(trigger_name, max_accounts=max_accounts)
        return payloads[0] if payloads else None

    def build(self, publisher_id: int, allow_non_cloaking: bool = False) -> Optional[CasePayload]:
        core = self._accessor.fetch_core(publisher_id)
        ge_scanned, project_ids = self._accessor.fetch_projects((core or {}).get("campaign_id"))
        ge_detected = self._accessor.alerts_exist(project_ids)
        spend = self._accessor.total_spent(publisher_id)

        plan_entry = self._plan_index.get_account(publisher_id) if self._plan_index else None
        plan_alerts = plan_entry.get("alerts", []) if plan_entry else []
        is_malicious_case = bool(plan_entry and self._has_cloaking_alerts(plan_alerts))
        if plan_entry and self._plan_index and not is_malicious_case and not allow_non_cloaking:
            LOGGER.info(
                "Skipping single-case build for publisher %s (no cloaking alerts in plan entry; use bulk cases)",
                publisher_id,
            )
            return None
        account_name = (core or {}).get("name") or "Unknown account"
        campaign_id = (core or {}).get("campaign_id")
        subject = self._build_subject(publisher_id, account_name, campaign_id, plan_entry)

        project_summary = ", ".join(project_ids) if project_ids else "None mapped"
        description = self._build_description(
            publisher_id,
            account_name,
            campaign_id,
            project_summary,
            ge_detected,
            ge_scanned,
            spend,
            plan_entry,
        )

        # Extract trigger details and campaign IDs from plan if available
        if plan_entry:
            alerts = plan_entry.get("alerts", []) or []
            if is_malicious_case:
                trigger_detail = "Malicious Cloaking"
            else:
                trigger_detail = (
                    (alerts[0].get("trigger_metadata") or "").strip()
                    or (alerts[0].get("alert_name") or "").strip()
                    or "Malicious URL Post-Click"
                ) if alerts else "Malicious URL Post-Click"
            
            # Get all campaign IDs from plan
            campaign_ids_list = plan_entry.get("campaign_ids") or []
            campaign_ids_str = ", ".join(str(cid) for cid in campaign_ids_list if cid)
            if not campaign_ids_str:
                campaign_ids_str = str(campaign_id) if campaign_id else "Unknown"
            
            # Set GE flags to Yes when using plan data
            ge_detected = "Yes"
            ge_scanned = "Yes"
        else:
            trigger_detail = "Suspected Fraud Activity"
            campaign_ids_str = (core or {}).get("campaign_id") or campaign_id

        payload = {
            "record_type": "0123o00000224fEAAQ",
            "case_type": "Fraud",
            "request_for": trigger_detail,
            "backstage_account_id": str(publisher_id),
            "flag_origin": "GeoEdge",
            "subject": subject,
            "description": description,
            "status": "New",
            "case_origin": "R&D Alert",
            "campaign_ids": campaign_ids_str,
            "ge_detected": ge_detected,
            "ge_scanned": ge_scanned,
        }
        if SF_OWNER_ID:
            payload["owner_id"] = SF_OWNER_ID
        return CasePayload(publisher_id=publisher_id, payload=payload)

    @staticmethod
    def _build_subject(
        publisher_id: int,
        account_name: str,
        campaign_id: Optional[int],
        plan_entry: Optional[dict[str, Any]],
    ) -> str:
        if plan_entry:
            account_id = plan_entry.get("account_id") or publisher_id
            account_label = plan_entry.get("account_name") or account_name or "Unknown account"
            return f"{account_id} - {account_label}"
        if campaign_id:
            return f"GeoEdge Cloaking - Campaign {campaign_id} ({publisher_id})"
        return f"GeoEdge Cloaking - {account_name} ({publisher_id})"

    @staticmethod
    def _parse_event_dt(value: Any) -> datetime:
        if isinstance(value, datetime):
            return value
        if not isinstance(value, str) or not value:
            return datetime.min
        candidates = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
        ]
        for fmt in candidates:
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
        return datetime.min

    def _build_description(
        self,
        publisher_id: int,
        account_name: str,
        campaign_id: Optional[int],
        project_summary: str,
        ge_detected: str,
        ge_scanned: str,
        spend: Optional[float],
        plan_entry: Optional[dict[str, Any]],
    ) -> str:
        if plan_entry:
            return self._plan_style_description(publisher_id, account_name, plan_entry)

        lines = [
            "GeoEdge flagged repeated Malicious Cloaking activity during the last 24h lookback.",
            f"Publisher: {publisher_id} ({account_name})",
            f"Campaign ID: {campaign_id or 'Unknown'}",
            f"GeoEdge projects mapped: {project_summary}",
            f"GeoEdge detected alerts this week: {ge_detected}",
            f"Latest scan run across mapped projects: {ge_scanned}",
        ]
        if spend is not None:
            lines.append(f"Lifetime spend (USD): {spend:,.2f}")
        lines.append(
            "Action: pause offending campaigns, investigate landing pages, and update case notes with remediation details."
        )
        return "\n".join(lines)

    def _plan_style_description(
        self,
        publisher_id: int,
        fallback_name: str,
        plan_entry: dict[str, Any],
    ) -> str:
        alerts = plan_entry.get("alerts", []) or []
        alert_count = plan_entry.get("alert_count") or len(alerts)
        campaign_ids = plan_entry.get("campaign_ids") or []
        campaign_line = ", ".join(str(cid) for cid in campaign_ids if cid) or "Unknown"
        account_id = plan_entry.get("account_id") or publisher_id
        account_name = plan_entry.get("account_name") or fallback_name or "Unknown account"

        detection_codes: list[str] = []
        for alert in alerts:
            location = alert.get("detection_location") or "Unknown"
            code = location.split(" - ")[0].strip() or "Unknown"
            if code not in detection_codes:
                detection_codes.append(code)
        detection_line = ", ".join(detection_codes) or "Unknown"

        trigger_category = (
            alerts[0].get("trigger_type_name", "Malicious URL Post-Click") if alerts else "Malicious URL Post-Click"
        )
        trigger_detail = ""
        for alert in alerts:
            candidate = (
                (alert.get("trigger_metadata") or "").strip()
                or (alert.get("alert_name") or "").strip()
                or ""
            )
            if "cloaking" in candidate.lower():
                trigger_detail = candidate
                break
        if not trigger_detail:
            if self._has_cloaking_alerts(alerts):
                trigger_detail = "Malicious Cloaking"
            else:
                trigger_detail = (
                    (alerts[0].get("trigger_metadata") or "").strip()
                    or (alerts[0].get("alert_name") or "").strip()
                    or trigger_category
                )

        latest_per_campaign: dict[str, dict[str, Any]] = {}
        for alert in alerts:
            campaign_key = str(alert.get("campaign_id", "Unknown"))
            parsed_dt = self._parse_event_dt(alert.get("event_datetime"))
            current = latest_per_campaign.get(campaign_key)
            if current is None or parsed_dt > current["dt"]:
                latest_per_campaign[campaign_key] = {
                    "dt": parsed_dt,
                    "url": alert.get("alert_details_url", ""),
                }
        bullet_lines: list[str] = []
        for cid in sorted(latest_per_campaign):
            url = latest_per_campaign[cid]["url"] or "Unavailable"
            bullet_lines.append(f"• Campaign {cid}: {url}")
        if not bullet_lines:
            bullet_lines.append("• No GeoEdge alert URLs were captured for this campaign.")

        lines = [
            "Malicious URL Post-Click Alerts - Daily Summary",
            "",
            f"Account ID: {account_id}",
            f"Account Name: {account_name}",
            f"Campaign IDs: {campaign_line}",
            f"Alert Count: {alert_count}",
            f"Detection Locations: {detection_line}",
            f"Trigger Category: {trigger_category}",
            f"Trigger Details: {trigger_detail}",
            "",
            "Alert URLs:",
            "Alert URLs (latest per campaign):",
        ]
        lines.extend(bullet_lines)

        other_triggers = plan_entry.get("other_triggers") or []
        other_activity = plan_entry.get("other_activity") or []
        if other_triggers or other_activity:
            lines.append("")
            if other_triggers:
                other_list = ", ".join(str(item) for item in other_triggers if item) or "Unknown"
                lines.append(f"Other Triggers: {other_list}")
            if other_activity:
                for entry in other_activity:
                    trigger = entry.get("trigger") or "Unknown"
                    alerts = entry.get("alerts") or []
                    lines.append(f"{trigger}:")
                    latest_per_campaign: dict[str, str] = {}
                    for alert in alerts:
                        campaign_id = str(alert.get("campaign_id", "Unknown"))
                        url = alert.get("alert_details_url") or "Unavailable"
                        if campaign_id not in latest_per_campaign:
                            latest_per_campaign[campaign_id] = url
                    if not latest_per_campaign:
                        lines.append("  • No alert URLs captured")
                        continue
                    for cid in sorted(latest_per_campaign):
                        lines.append(f"  • Campaign {cid}: {latest_per_campaign[cid]}")
        return "\n".join(lines)


class CasePoster:
    def __init__(self, dry_run: bool = False) -> None:
        self._session = requests.Session()
        self._session.headers.update({"Content-Type": "application/json", "API-TOKEN": SF_API_TOKEN})
        self._dry_run = dry_run

    def post(self, case_payload: CasePayload) -> CaseResult:
        if self._dry_run:
            LOGGER.info("[DRY-RUN] Would create case for publisher %s", case_payload.publisher_id)
            return CaseResult(case_payload.publisher_id, True, response={"dry_run": True})

        backoff = INITIAL_BACKOFF
        for attempt in range(1, MAX_CASE_RETRIES + 1):
            if DEBUG_CASE_PAYLOAD:
                payload_dump = json.dumps(case_payload.payload, ensure_ascii=False, default=str)
                LOGGER.info("Posting case payload for %s: %s", case_payload.publisher_id, payload_dump)
            response = self._session.post(SF_CASE_URL, json=case_payload.payload, timeout=30)
            status = response.status_code
            try:
                body = response.json()
            except ValueError:
                body = {"raw": response.text}

            if 200 <= status < 300:
                case_id = None
                if isinstance(body, dict):
                    case_id = body.get("id") or body.get("case_id") or body.get("sf_case_id")
                if case_id:
                    LOGGER.info(
                        "Salesforce case created for %s (HTTP %s, id=%s)",
                        case_payload.publisher_id,
                        status,
                        case_id,
                    )
                else:
                    LOGGER.info("Salesforce case created for %s (HTTP %s)", case_payload.publisher_id, status)
                return CaseResult(case_payload.publisher_id, True, response=body)

            LOGGER.warning(
                "Salesforce returned %s for publisher %s (attempt %s/%s)",
                status,
                case_payload.publisher_id,
                attempt,
                MAX_CASE_RETRIES,
            )

            if status != 429 and status < 500:
                return CaseResult(case_payload.publisher_id, False, response=body, error=str(body))

            if attempt < MAX_CASE_RETRIES:
                LOGGER.info("Sleeping %.1fs before retry", backoff)
                time.sleep(backoff)
                backoff *= 2
            else:
                return CaseResult(case_payload.publisher_id, False, response=body, error=str(body))


# ---------------------------------------------------------------------------
# Batch runner
# ---------------------------------------------------------------------------
class CaseRunner:
    def __init__(
        self,
        builder: CaseBuilder,
        poster: CasePoster,
        batch_sleep: float = 0,
        progress: Optional[ProgressTracker] = None,
        resume: bool = False,
    ) -> None:
        self._builder = builder
        self._poster = poster
        self._batch_sleep = batch_sleep
        self._progress = progress
        self._resume = resume

    def run(self, publisher_ids: Sequence[int]) -> list[CaseResult]:
        results: list[CaseResult] = []
        for idx, pub_id in enumerate(publisher_ids, start=1):
            progress_key = f"publisher:{pub_id}"
            if self._resume and self._progress and self._progress.has(progress_key):
                LOGGER.info("Skipping publisher %s (already recorded in progress)", pub_id)
                results.append(CaseResult(pub_id, False, error="Skipped (resume)"))
                continue
            LOGGER.info("Processing publisher %s (%s/%s)", pub_id, idx, len(publisher_ids))
            payload = self._builder.build(pub_id)
            if payload is None:
                result = CaseResult(pub_id, False, error="Skipped")
                results.append(result)
                if self._progress:
                    self._progress.record(progress_key, result)
                continue
            result = self._poster.post(payload)
            results.append(result)
            if self._progress:
                self._progress.record(progress_key, result)
            if self._batch_sleep and idx < len(publisher_ids):
                LOGGER.debug("Sleeping %.1fs between publishers", self._batch_sleep)
                time.sleep(self._batch_sleep)
        return results

    def close(self, publisher_ids: Sequence[int], status: str) -> list[CaseResult]:
        results: list[CaseResult] = []
        for idx, pub_id in enumerate(publisher_ids, start=1):
            progress_key = f"close:{pub_id}"
            if self._resume and self._progress and self._progress.has(progress_key):
                LOGGER.info("Skipping publisher %s (already recorded in progress)", pub_id)
                results.append(CaseResult(pub_id, False, error="Skipped (resume)"))
                continue
            LOGGER.info("Closing case for publisher %s (%s/%s)", pub_id, idx, len(publisher_ids))
            payload = self._builder.build(pub_id, allow_non_cloaking=True)
            if payload is None:
                result = CaseResult(pub_id, False, error="Skipped")
                results.append(result)
                if self._progress:
                    self._progress.record(progress_key, result)
                continue
            payload.payload["status"] = status
            result = self._poster.post(payload)
            results.append(result)
            if self._progress:
                self._progress.record(progress_key, result)
            if self._batch_sleep and idx < len(publisher_ids):
                LOGGER.debug("Sleeping %.1fs between publishers", self._batch_sleep)
                time.sleep(self._batch_sleep)
        return results

    def run_bulk_trigger(
        self,
        trigger_name: str,
        max_accounts: Optional[int] = None,
        max_accounts_per_case: Optional[int] = None,
        max_campaign_ids_len: Optional[int] = None,
    ) -> list[CaseResult]:
        progress_key = f"bulk:{trigger_name}"
        if self._resume and self._progress and self._progress.has(progress_key):
            LOGGER.info("Skipping bulk trigger %s (already recorded in progress)", trigger_name)
            return [CaseResult(0, False, error="Skipped (resume)")]
        payloads = self._builder.build_bulk_trigger_cases(
            trigger_name,
            max_accounts=max_accounts,
            max_accounts_per_case=max_accounts_per_case,
            max_campaign_ids_len=max_campaign_ids_len,
        )
        if not payloads:
            return [CaseResult(0, False, error=f"No bulk trigger case found for '{trigger_name}'")]
        results: list[CaseResult] = []
        for payload in payloads:
            results.append(self._poster.post(payload))
        if self._progress:
            self._progress.record(progress_key, CaseResult(0, all(r.success for r in results)))
        return results

    def close_bulk_trigger(
        self,
        trigger_name: str,
        status: str,
        max_accounts: Optional[int] = None,
        max_accounts_per_case: Optional[int] = None,
        max_campaign_ids_len: Optional[int] = None,
    ) -> list[CaseResult]:
        progress_key = f"bulk_close:{trigger_name}"
        if self._resume and self._progress and self._progress.has(progress_key):
            LOGGER.info("Skipping bulk trigger %s (already recorded in progress)", trigger_name)
            return [CaseResult(0, False, error="Skipped (resume)")]
        payloads = self._builder.build_bulk_trigger_cases(
            trigger_name,
            max_accounts=max_accounts,
            max_accounts_per_case=max_accounts_per_case,
            max_campaign_ids_len=max_campaign_ids_len,
        )
        if not payloads:
            return [CaseResult(0, False, error=f"No bulk trigger case found for '{trigger_name}'")]
        results: list[CaseResult] = []
        for payload in payloads:
            payload.payload["status"] = status
            results.append(self._poster.post(payload))
        if self._progress:
            self._progress.record(progress_key, CaseResult(0, all(r.success for r in results)))
        return results


# ---------------------------------------------------------------------------
# CLI utilities
# ---------------------------------------------------------------------------
def _parse_publisher_ids(args: argparse.Namespace, plan_index: Optional[CasePlanIndex]) -> list[int]:
    if args.from_plan:
        if plan_index is None:
            raise ValueError("--from-plan requires a valid --case-plan file")
        ids = plan_index.list_malicious_account_ids()
        if args.max_from_plan is not None:
            ids = ids[: args.max_from_plan]
        if not ids:
            raise ValueError("No malicious cloaking publisher IDs found in case plan")
        return ids
    if args.publisher_ids:
        return [int(pid.strip()) for pid in args.publisher_ids]
    if args.publisher_file:
        path = Path(args.publisher_file)
        if not path.exists():
            raise FileNotFoundError(f"Publisher list file not found: {path}")
        ids: list[int] = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                ids.append(int(line))
        return ids
    raise ValueError("No publisher IDs supplied")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create Salesforce cases for suspicious publishers")
    parser.add_argument("publisher_ids", nargs="*", help="Publisher/account IDs to process")
    parser.add_argument("--publisher-file", help="Path to file containing publisher IDs (one per line)")
    parser.add_argument("--dry-run", action="store_true", help="Build payloads but do not call Salesforce")
    parser.add_argument("--batch-sleep", type=float, default=BATCH_SLEEP, help="Seconds to sleep between publishers")
    parser.add_argument(
        "--close",
        action="store_true",
        help="Close cases instead of creating them (uses the same Workato endpoint).",
    )
    parser.add_argument(
        "--close-status",
        default="Closed",
        help="Status value to set when closing cases (default: Closed).",
    )
    parser.add_argument(
        "--from-plan",
        action="store_true",
        help="Use publisher IDs found in the case plan JSON instead of explicit IDs.",
    )
    parser.add_argument(
        "--max-from-plan",
        type=int,
        help="Limit the number of publisher IDs loaded from the case plan.",
    )
    parser.add_argument(
        "--case-plan",
        default=str(CASE_PLAN_PATH),
        help="Path to the JSON output from main.py (used to enrich Salesforce descriptions)",
    )
    parser.add_argument(
        "--bulk-trigger",
        help="Create a single bulk trigger case for the given trigger name.",
    )
    parser.add_argument(
        "--bulk-max-accounts",
        type=int,
        help="Limit number of accounts included in a bulk trigger case.",
    )
    parser.add_argument(
        "--bulk-batch-size",
        type=int,
        help="Maximum accounts per bulk trigger case (defaults to env BULK_MAX_ACCOUNTS_PER_CASE).",
    )
    parser.add_argument(
        "--bulk-max-campaign-ids-len",
        type=int,
        help="Max length for campaign_ids field before splitting (defaults to env BULK_MAX_CAMPAIGN_IDS_LEN).",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from last run using progress file (skips already processed items).",
    )
    parser.add_argument(
        "--progress-file",
        default=PROGRESS_FILE_DEFAULT,
        help="Path to progress file for resume support (default: case_creation_progress.jsonl).",
    )
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
def main(argv: Optional[Sequence[str]] = None) -> None:
    args = parse_args(argv)
    plan_path = Path(args.case_plan) if args.case_plan else None

    db_client = DatabaseClient()
    accessor = CaseDataAccessor(db_client)
    plan_index = CasePlanIndex(plan_path)
    builder = CaseBuilder(accessor, plan_index=plan_index)
    poster = CasePoster(dry_run=args.dry_run)
    progress = ProgressTracker(Path(args.progress_file)) if args.progress_file else None
    runner = CaseRunner(builder, poster, batch_sleep=args.batch_sleep, progress=progress, resume=args.resume)

    try:
        if args.bulk_trigger:
            publisher_ids = []
            if args.close:
                results = runner.close_bulk_trigger(
                    args.bulk_trigger,
                    status=args.close_status,
                    max_accounts=args.bulk_max_accounts,
                    max_accounts_per_case=args.bulk_batch_size,
                    max_campaign_ids_len=args.bulk_max_campaign_ids_len,
                )
            else:
                results = runner.run_bulk_trigger(
                    args.bulk_trigger,
                    max_accounts=args.bulk_max_accounts,
                    max_accounts_per_case=args.bulk_batch_size,
                    max_campaign_ids_len=args.bulk_max_campaign_ids_len,
                )
        else:
            publisher_ids = _parse_publisher_ids(args, plan_index)
            if args.close:
                results = runner.close(publisher_ids, status=args.close_status)
            else:
                results = runner.run(publisher_ids)
            if args.from_plan:
                for trigger in plan_index.list_bulk_triggers():
                    if args.close:
                        results.extend(
                            runner.close_bulk_trigger(
                                trigger,
                                status=args.close_status,
                                max_accounts=args.bulk_max_accounts,
                                max_accounts_per_case=args.bulk_batch_size,
                                max_campaign_ids_len=args.bulk_max_campaign_ids_len,
                            )
                        )
                    else:
                        results.extend(
                            runner.run_bulk_trigger(
                                trigger,
                                max_accounts=args.bulk_max_accounts,
                                max_accounts_per_case=args.bulk_batch_size,
                                max_campaign_ids_len=args.bulk_max_campaign_ids_len,
                            )
                        )
    finally:
        db_client.close()

    successes = sum(1 for res in results if res.success)
    failures = [res for res in results if not res.success]

    print("\nSummary")
    print("--------")
    print(f"Publishers processed: {len(results)}")
    print(f"Cases created:        {successes}")
    print(f"Failures/skipped:     {len(failures)}")

    if failures:
        print("\nFailure details:")
        for failure in failures:
            print(f" - Publisher {failure.publisher_id}: {failure.error}")


if __name__ == "__main__":  # pragma: no cover
    try:
        main()
    except Exception as exc:  # Provide explicit log for unexpected crashes
        LOGGER.exception("Run aborted: %s", exc)
        sys.exit(1)
