"""A per-client token bucket.

Everything here is reachable without an account: /notarize in free mode costs
nothing, and /challenge is free in every mode. Without a limit, one caller can
fill the witness log or exhaust the challenge ceiling and deny service to
paying customers. The x402 gate is not a rate limit — it only applies when
charging is on, and it runs *after* verification work has already happened.

Deliberately in-process and dependency-free. It matches the deployment the
README prescribes (a single process); a multi-process notary needs a shared
limiter, and the README says so.
"""

import time
from collections import OrderedDict

# Bounded so the limiter cannot itself become the memory-growth lever it
# exists to prevent. Least-recently-seen clients are evicted first.
MAX_TRACKED_CLIENTS = 50_000


class TokenBucket:
    """`rate` requests per second, bursting to `capacity`."""

    def __init__(self, capacity: int, rate: float, *, now=time.monotonic):
        self.capacity = capacity
        self.rate = rate
        self._now = now
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()

    def allow(self, client: str) -> bool:
        now = self._now()
        tokens, last = self._buckets.get(client, (float(self.capacity), now))
        tokens = min(self.capacity, tokens + (now - last) * self.rate)
        if tokens < 1.0:
            self._buckets[client] = (tokens, now)
            self._buckets.move_to_end(client)
            return False
        self._buckets[client] = (tokens - 1.0, now)
        self._buckets.move_to_end(client)
        while len(self._buckets) > MAX_TRACKED_CLIENTS:
            self._buckets.popitem(last=False)
        return True


def client_key(request) -> str:
    """Who to bucket by.

    X-Forwarded-For is honoured only when the operator has said a proxy is in
    front (LETHE_NOTARY_TRUST_PROXY). Trusting it unconditionally would let any
    caller mint a fresh identity per request by setting the header, which turns
    the rate limiter off for exactly the people it is meant to stop.
    """
    if request.app.state.notary.trust_proxy:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
