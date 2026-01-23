#!/usr/bin/env python3
"""End-to-end runner: fetch GeoEdge alerts, build plan, create cases with auto-retry/resume."""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from main import (
    ALERT_LOOKBACK_HOURS,
    TRIGGER_CATEGORY_NAME,
    build_case_plan,
    enrich_alerts_with_account_info,
    fetch_malicious_cloaking_alerts,
    filter_trigger_category,
    log_message,
)
from case_creator import (
    BATCH_SLEEP,
    CASE_PLAN_PATH,
    DatabaseClient,
    CaseDataAccessor,
    CasePlanIndex,
    CaseBuilder,
    CasePoster,
    CaseRunner,
    ProgressTracker,
    PROGRESS_FILE_DEFAULT,
)
from email_reporter import GeoEdgeEmailReporter


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run GeoEdge fetch + Salesforce case creation end-to-end")
    parser.add_argument("--hours", type=int, default=ALERT_LOOKBACK_HOURS)
    parser.add_argument("--case-plan", default=str(CASE_PLAN_PATH))
    parser.add_argument("--progress-file", default=str(PROGRESS_FILE_DEFAULT))
    parser.add_argument("--reset-progress", action="store_true", help="Clear progress file before running")
    parser.add_argument("--dry-run", action="store_true", help="Build payloads but do not create Salesforce cases")
    parser.add_argument(
        "--max-runtime-hours",
        type=float,
        default=6.0,
        help="Max runtime window before failing the run (default: 6h)",
    )
    parser.add_argument(
        "--min-sleep",
        type=float,
        default=60.0,
        help="Minimum sleep between retry passes (seconds)",
    )
    parser.add_argument(
        "--max-sleep",
        type=float,
        default=1800.0,
        help="Maximum sleep between retry passes (seconds)",
    )
    return parser.parse_args(argv)


def _write_plan(plan: dict[str, Any], path: Path) -> None:
    path.write_text(json.dumps(plan, indent=2), encoding="utf-8")


def _load_plan_json(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    marker_pos = text.rfind('"project"')
    if marker_pos == -1:
        raise RuntimeError("Case plan missing project marker")
    start = text.rfind("{", 0, marker_pos)
    if start == -1:
        raise RuntimeError("Case plan does not contain JSON object")
    return json.loads(text[start:])


def _compute_missing(
    plan: dict[str, Any],
    progress_path: Path,
) -> tuple[list[str], list[str], list[str], list[dict[str, Any]]]:
    mc_accounts = [str(c.get("account_id")) for c in plan.get("malicious_cloaking_cases", [])]
    bulk_triggers = [c.get("trigger") for c in plan.get("bulk_trigger_cases", [])]

    progress: dict[str, dict[str, Any]] = {}
    if progress_path.exists():
        for line in progress_path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            key = entry.get("key")
            if key:
                progress[key] = entry

    mc_done = {
        k.split(":", 1)[1]
        for k, v in progress.items()
        if k.startswith("publisher:") and bool(v.get("success"))
    }
    bulk_done = {
        k.split(":", 1)[1]
        for k, v in progress.items()
        if k.startswith("bulk:") and bool(v.get("success"))
    }

    mc_known = [aid for aid in mc_accounts if aid.isdigit()]
    mc_unknown = [aid for aid in mc_accounts if not aid.isdigit()]

    missing_mc = [aid for aid in mc_known if aid not in mc_done]
    missing_bulk = [t for t in bulk_triggers if t not in bulk_done]
    non_retriable: list[dict[str, Any]] = []
    for key, entry in progress.items():
        status = entry.get("status_code")
        if status in {400, 404}:
            non_retriable.append({"key": key, "status": status, "error": entry.get("error")})

    return missing_mc, missing_bulk, mc_unknown, non_retriable


def _run_case_creation(plan_path: Path, progress_path: Path, dry_run: bool) -> None:
    db_client = DatabaseClient()
    accessor = CaseDataAccessor(db_client)
    plan_index = CasePlanIndex(plan_path)
    builder = CaseBuilder(accessor, plan_index=plan_index)
    poster = CasePoster(dry_run=dry_run)
    progress = ProgressTracker(progress_path)
    runner = CaseRunner(
        builder,
        poster,
        batch_sleep=BATCH_SLEEP,
        progress=progress,
        resume=True,
        plan_id=plan_index.get_plan_id(),
    )

    try:
        publisher_ids = plan_index.list_malicious_account_ids()
        runner.run(publisher_ids)
        for trigger in plan_index.list_bulk_triggers():
            runner.run_bulk_trigger(trigger)
    finally:
        db_client.close()


def run_once(args: argparse.Namespace) -> None:
    plan_path = Path(args.case_plan)
    progress_path = Path(args.progress_file)

    if args.reset_progress and progress_path.exists():
        progress_path.unlink(missing_ok=True)

    log_message(f"Starting end-to-end run (lookback={args.hours}h)")
    alerts = fetch_malicious_cloaking_alerts(lookback_hours=args.hours)
    if not alerts:
        raise RuntimeError("GeoEdge returned no alerts for requested window")

    enriched_alerts = enrich_alerts_with_account_info(alerts)
    if not enriched_alerts:
        raise RuntimeError("No alerts could be enriched with account metadata")

    filtered_alerts = filter_trigger_category(enriched_alerts, TRIGGER_CATEGORY_NAME)
    if not filtered_alerts:
        raise RuntimeError(f"No alerts matched trigger category '{TRIGGER_CATEGORY_NAME}'")

    plan = build_case_plan(filtered_alerts)
    _write_plan(plan, plan_path)

    reporter = GeoEdgeEmailReporter()
    deadline = time.time() + (args.max_runtime_hours * 3600)
    sleep_seconds = args.min_sleep

    while True:
        _run_case_creation(plan_path, progress_path, args.dry_run)
        plan_loaded = _load_plan_json(plan_path)
        missing_mc, missing_bulk, unknown_mc, non_retriable = _compute_missing(plan_loaded, progress_path)

        if unknown_mc:
            log_message(f"Skipped {len(unknown_mc)} cloaking accounts without IDs: {', '.join(unknown_mc[:5])}")

        if non_retriable:
            html_body = "".join(
                [
                    "<p>Non-retriable failures detected.</p>",
                    "<ul>",
                    *[f"<li>{item['key']} (status {item['status']}): {item['error']}</li>" for item in non_retriable],
                    "</ul>",
                ]
            )
            reporter.send_run_report(
                subject="GeoEdge Case Run Failed",
                html_body=html_body,
            )
            raise RuntimeError("Non-retriable failures detected")

        if not missing_mc and not missing_bulk:
            log_message("All planned cases were created successfully.")
            reporter.send_run_report(
                subject="GeoEdge Case Run Completed",
                html_body="<p>All planned cases were created successfully.</p>",
            )
            return

        if time.time() >= deadline:
            html_body = (
                f"<p>Case creation incomplete after {args.max_runtime_hours}h.</p>"
                f"<p>Missing cloaking accounts: {len(missing_mc)}</p>"
                f"<p>Missing bulk triggers: {len(missing_bulk)}</p>"
            )
            reporter.send_run_report(
                subject="GeoEdge Case Run Failed",
                html_body=html_body,
            )
            raise RuntimeError("Case creation incomplete after max runtime window")

        log_message(
            f"Retrying missing items: cloaking={len(missing_mc)}, bulk={len(missing_bulk)}"
        )
        time.sleep(min(sleep_seconds, args.max_sleep))
        sleep_seconds = min(sleep_seconds * 2, args.max_sleep)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    run_once(args)


if __name__ == "__main__":
    main()
