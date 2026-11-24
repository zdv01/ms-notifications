import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self):
        self._events = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        return self.allow_all([key], limit, window_seconds)

    def allow_all(self, keys: list[str], limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        with self._lock:
            for key in keys:
                events = self._events[key]
                while events and now - events[0] >= window_seconds:
                    events.popleft()
                if len(events) >= limit:
                    return False
            for key in keys:
                self._events[key].append(now)
            return True
