"""A minimal in-process scheduler for periodic ingestion (`blackshield-signatures schedule`).

One loop, one job: run, then wait ``interval`` seconds (+/- 10 % jitter so replicas do not
synchronize). A failed run is logged and retried at the next tick. SIGTERM / SIGINT stop the
loop between runs. Run exactly one scheduler per deployment; concurrent writers are safe but
waste MalwareBazaar quota.
"""

import logging
import random
import signal
import threading
from collections.abc import Callable

logger = logging.getLogger(__name__)


def run_periodically(
    job: Callable[[], object],
    *,
    interval: float,
    stop: threading.Event | None = None,
    jitter: float = 0.1,
    max_runs: int | None = None,
    rng: Callable[[], float] = random.random,
) -> int:
    """Run ``job`` until ``stop`` is set (or ``max_runs`` is reached). Returns the run count."""
    stop = stop or threading.Event()
    runs = 0
    while not stop.is_set():
        runs += 1
        try:
            job()
        except Exception:
            logger.exception("scheduled ingest failed")
        if max_runs is not None and runs >= max_runs:
            break
        wait = interval * (1 + jitter * (2 * rng() - 1))
        logger.info("next scheduled ingest", extra={"in_seconds": round(wait)})
        stop.wait(wait)
    return runs


def stop_on_signals(stop: threading.Event) -> None:
    def handler(signum: int, _frame: object) -> None:
        logger.info("stopping scheduler", extra={"signal": signal.Signals(signum).name})
        stop.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, handler)
