import os
import unittest

os.environ.setdefault("SCANNER_SERVICE_TOKEN", "scanner-token")
os.environ.setdefault("ORCHESTRATOR_API_KEY", "dev-orchestrator-api-key")

from services.event_bus import cleanup_scan_stream, close_scan_stream, publish_scan_event, subscribe, unsubscribe


class EventBusTests(unittest.TestCase):
    def test_publish_event_reaches_scan_stream(self) -> None:
        scan_id = "scan-bus"
        subscriber_queue, backlog = subscribe(scan_id)
        self.assertEqual(backlog, [])

        event = publish_scan_event(scan_id, "planner.started", "Planner started.", {"phase": "planner"})
        queued_event = subscriber_queue.get(timeout=1)

        self.assertEqual(queued_event.scan_id, scan_id)
        self.assertEqual(queued_event.type, "planner.started")
        self.assertEqual(event.type, queued_event.type)

        unsubscribe(scan_id, subscriber_queue)
        cleanup_scan_stream(scan_id)

    def test_close_stream_notifies_subscribers(self) -> None:
        scan_id = "scan-close"
        subscriber_queue, _ = subscribe(scan_id)

        close_scan_stream(scan_id, cleanup_delay_seconds=0.01)
        sentinel = subscriber_queue.get(timeout=1)

        self.assertFalse(hasattr(sentinel, "model_dump"))

        unsubscribe(scan_id, subscriber_queue)
        cleanup_scan_stream(scan_id)


if __name__ == "__main__":
    unittest.main()
