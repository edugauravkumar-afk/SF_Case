#!/usr/bin/env python3
"""Daily scheduler for end-to-end GeoEdge case creation."""
from __future__ import annotations

import os
import time
from pathlib import Path

import schedule

from run_daily import _parse_args, run_once

LAST_RUN_PATH = Path("/tmp/geoedge_last_run.txt")


def _read_last_run() -> float | None:
    if not LAST_RUN_PATH.exists():
        return None
    try:
        return float(LAST_RUN_PATH.read_text().strip())
    except Exception:
        return None


def _write_last_run(ts: float) -> None:
    try:
        LAST_RUN_PATH.write_text(str(ts))
    except Exception:
        pass


class GeoEdgeDailyService:
    def __init__(self, run_time: str = "09:00") -> None:
        self.run_time = run_time
        self.running = True

    def run_daily_check(self) -> None:
        args = _parse_args(None)
        run_once(args)
        _write_last_run(time.time())

    def start(self) -> None:
        schedule.every().day.at(self.run_time).do(self.run_daily_check)

        last_run = _read_last_run()
        if last_run is None or (time.time() - last_run) > 23 * 3600:
            self.run_daily_check()

        while self.running:
            schedule.run_pending()
            time.sleep(60)


if __name__ == "__main__":
    run_time = os.getenv("DAILY_RUN_TIME", "09:00")
    GeoEdgeDailyService(run_time=run_time).start()
