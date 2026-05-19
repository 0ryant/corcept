class RateLimiter:
    def __init__(self, limit: int, window_seconds: int):
        self.limit = limit
        self.window_seconds = window_seconds
        self.events = {}

    def allow(self, user: str, now: int) -> bool:
        window_start = now - self.window_seconds
        events = [t for t in self.events.get(user, []) if t > window_start]
        if len(events) >= self.limit:
            self.events[user] = events
            return False
        events.append(now)
        self.events[user] = events
        return True
