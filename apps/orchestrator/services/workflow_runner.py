import logging
import threading

from graph.workflow import run_enriched_report_workflow
from services.event_bus import close_scan_stream, ensure_scan_stream, publish_scan_event


logger = logging.getLogger(__name__)


class _WorkflowRun:
    def __init__(self) -> None:
        self.done = threading.Event()
        self.result: dict | None = None
        self.error: Exception | None = None
        self.thread: threading.Thread | None = None


_workflow_runs: dict[str, _WorkflowRun] = {}
_workflow_runs_lock = threading.Lock()


def start_scan_workflow(scan_id: str) -> None:
    with _workflow_runs_lock:
        existing = _workflow_runs.get(scan_id)
        if existing is not None and not existing.done.is_set():
            logger.info("scan workflow already running scan_id=%s", scan_id)
            return
        if existing is not None and existing.done.is_set():
            logger.info("scan workflow already completed scan_id=%s", scan_id)
            return

        run = _WorkflowRun()
        thread = threading.Thread(target=_run_scan_workflow, args=(scan_id, run), daemon=True)
        run.thread = thread
        _workflow_runs[scan_id] = run

    ensure_scan_stream(scan_id)
    logger.info("scan workflow thread starting scan_id=%s", scan_id)
    thread.start()


def run_or_wait_scan_workflow(scan_id: str) -> dict:
    start_scan_workflow(scan_id)

    with _workflow_runs_lock:
        run = _workflow_runs[scan_id]

    logger.info("waiting for scan workflow scan_id=%s", scan_id)
    run.done.wait()
    if run.error is not None:
        logger.error("scan workflow completed with error scan_id=%s error=%s", scan_id, run.error)
        raise run.error

    logger.info("scan workflow result available scan_id=%s", scan_id)
    return run.result or {}


def _run_scan_workflow(scan_id: str, run: _WorkflowRun) -> None:
    logger.info("scan workflow started scan_id=%s", scan_id)
    publish_scan_event(scan_id, "scan.started", "Scan workflow started.", {})

    try:
        run.result = run_enriched_report_workflow(scan_id)
        logger.info("scan workflow completed scan_id=%s result_keys=%s", scan_id, sorted(run.result.keys()))
    except Exception as exc:
        logger.exception("scan workflow failed scan_id=%s", scan_id)
        run.error = exc
        publish_scan_event(
            scan_id,
            "scan.completed",
            "Scan workflow completed with an error.",
            {
                "status": "failed",
                "error": str(exc),
            },
        )
    finally:
        run.done.set()
        close_scan_stream(scan_id)
