from rate_limiter import RateLimiter

def test_nth_request_allowed_and_next_blocked():
    rl = RateLimiter(limit=3, window_seconds=10)
    assert rl.allow('u', 100) is True
    assert rl.allow('u', 101) is True
    assert rl.allow('u', 102) is True
    assert rl.allow('u', 103) is False

def test_old_events_expire():
    rl = RateLimiter(limit=2, window_seconds=10)
    assert rl.allow('u', 0) is True
    assert rl.allow('u', 1) is True
    assert rl.allow('u', 11) is True
