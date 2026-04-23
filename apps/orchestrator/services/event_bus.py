import json
import threading
from collections import deque
from datetime import datetime, timezone
from queue import Queue
from typing import Final

from schemas.events import ScanWorkflowEvent


_CLOSE_SENTINEL: Final = object()
_DEFAULT_HISTORY_LIMIT: Final = 100
_DEFAULT_CLEANUP_DELAY_SECONDS: Final = 30.0


class _ScanStreamState:
    def __init__(self) -> None:
        self.history: deque[ScanWorkflowEvent] = deque(maxlen=_DEFAULT_HISTORY_LIMIT)
        self.subscribers: list[Queue] = []
        self.closed = False
        self.cleanup_timer: threading.Timer | None = None


_streams: dict[str, _ScanStreamState] = {}
_streams_lock = threading.Lock()


def ensure_scan_stream(scan_id: str) -> None:
    with _streams_lock:
        state = _streams.get(scan_id)
        if state is None:
            _streams[scan_id] = _ScanStreamState()
            return

        if state.cleanup_timer is not None:
            state.cleanup_timer.cancel()
            state.cleanup_timer = None
        state.closed = False


def subscribe(scan_id: str) -> tuple[Queue, list[ScanWorkflowEvent]]:
    subscriber_queue: Queue = Queue()
    with _streams_lock:
        state = _streams.get(scan_id)
        if state is None:
            state = _ScanStreamState()
            _streams[scan_id] = state

        backlog = list(state.history)
        state.subscribers.append(subscriber_queue)
        if state.closed:
            subscriber_queue.put(_CLOSE_SENTINEL)

    return subscriber_queue, backlog


def unsubscribe(scan_id: str, subscriber_queue: Queue) -> None:
    with _streams_lock:
        state = _streams.get(scan_id)
        if state is None:
            return

        state.subscribers = [queue for queue in state.subscribers if queue is not subscriber_queue]


def publish_scan_event(scan_id: str, event_type: str, message: str, metadata: dict | None = None) -> ScanWorkflowEvent:
    event = ScanWorkflowEvent(
        scan_id=scan_id,
        type=event_type,
        message=message,
        timestamp=datetime.now(timezone.utc),
        metadata=metadata or {},
    )

    ensure_scan_stream(scan_id)
    with _streams_lock:
        state = _streams[scan_id]
        state.history.append(event)
        subscribers = list(state.subscribers)

    for subscriber_queue in subscribers:
        subscriber_queue.put(event)

    return event


def close_scan_stream(scan_id: str, cleanup_delay_seconds: float = _DEFAULT_CLEANUP_DELAY_SECONDS) -> None:
    with _streams_lock:
        state = _streams.get(scan_id)
        if state is None:
            return

        state.closed = True
        subscribers = list(state.subscribers)
        if state.cleanup_timer is not None:
            state.cleanup_timer.cancel()

        state.cleanup_timer = threading.Timer(cleanup_delay_seconds, cleanup_scan_stream, args=(scan_id,))
        state.cleanup_timer.daemon = True
        state.cleanup_timer.start()

    for subscriber_queue in subscribers:
        subscriber_queue.put(_CLOSE_SENTINEL)


def cleanup_scan_stream(scan_id: str) -> None:
    with _streams_lock:
        state = _streams.pop(scan_id, None)
        if state is None:
            return

        if state.cleanup_timer is not None:
            state.cleanup_timer.cancel()


def is_scan_stream_closed(scan_id: str) -> bool:
    with _streams_lock:
        state = _streams.get(scan_id)
        if state is None:
            return True

        return state.closed


def format_sse_data(event: ScanWorkflowEvent) -> str:
    return f"data: {json.dumps(event.model_dump(mode='json'))}\n\n"
