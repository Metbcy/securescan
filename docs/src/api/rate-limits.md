# Rate limits

`POST /api/scans` (and the forward-compatible `POST /api/v1/scans`
mount) is rate-limited with an in-memory token bucket. Read endpoints
(list scans, get findings, dashboard, sbom) are **not** rate-limited
— they are cheap and benefit from being responsive during incident
triage.

<!-- toc -->

## Defaults

- **60 requests per minute** sustained.
- **Burst of 10** — a client that's been silent can fire 10 immediately
  before the bucket starts metering.
- **Per API key** when `SECURESCAN_API_KEY` is set or DB keys are in
  use; **per client IP** in dev mode.

## Override

```bash
export SECURESCAN_RATE_LIMIT_PER_MIN=60     # sustained rate
export SECURESCAN_RATE_LIMIT_BURST=10       # burst capacity
export SECURESCAN_RATE_LIMIT_ENABLED=true   # set to false to disable
```

The env-var-driven knobs let an operator tune without code changes.
They are read once at backend startup; restart to apply.

## Successful response headers

Every successful `POST /scans` response carries:

```http
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 47
X-RateLimit-Reset: 1730230885
```

`X-RateLimit-Reset` is the unix timestamp when the bucket fully
refills. Clients can watch `Remaining` to back off proactively.

## When the bucket is empty

```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
Retry-After: 7
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1730230885

{
  "detail": "Rate limit exceeded",
  "retry_after": 7,
  "limit_per_min": 60
}
```

`Retry-After` is in seconds — wait that long, retry, succeed.
Well-behaved clients honor the header rather than guessing.

```admonish tip title="Use Retry-After, not your own backoff"
A handcrafted exponential backoff will under- or over-shoot the
bucket refill time; the server's `Retry-After` is the exact
duration to the next available slot. Particularly important on
periodic CI runs that all start near the top of the hour.
```

## Why only `POST /scans`?

Starting a scan kicks off a CPU-and-IO-heavy background task —
fork the scanner subprocesses, spin the orchestrator, write findings.
A flood of `POST /scans` is a real DoS vector.

`GET` endpoints are read-only, indexed, and bounded by the size of
the existing data. They are cheap. Rate-limiting them would mostly
hurt incident triage (when a SecureScan operator is hammering the
findings table to find the regression).

## Per-key isolation

The bucket key is the **principal**:

- `key_id` for DB-issued keys.
- The string `"env"` for the legacy env-var path (a single shared
  bucket).
- The client IP in dev mode (no auth configured).

So a misbehaving CI runner with one key cannot starve another
runner using a different key. The single shared env-var key,
however, is one bucket — switch to per-CI DB keys for isolation.

## Bounded memory

The bucket store has hard limits:

- **Max 10K live keys** — a key-rotation or DoS pattern with many
  unique keys can't grow memory without limit.
- **1h idle TTL with LRU eviction** — buckets that haven't been hit
  in an hour are dropped. They re-initialize at full capacity if
  the key reappears.

## Disabling rate limiting

Set `SECURESCAN_RATE_LIMIT_ENABLED=false` to turn it off. Useful in
test fixtures and when you've put SecureScan behind a smarter rate
limiter (envoy / nginx / Traefik) that handles this concern at the
edge.

```admonish important
Do **not** disable rate limiting on a deployment that allows
unauthenticated `POST /scans` (i.e. dev mode + AUTH_REQUIRED=0). The
bucket is the only thing standing between a curl loop and a
fork-bombed orchestrator. Either keep rate limiting on, or require
auth.
```

## In the dashboard

The dashboard's New Scan page does not poll `POST /scans` — it
fires once per click. The 60/min default is generous enough that a
human triggering scans manually never hits it.

For a CI runner, 60/min with a burst of 10 supports about one scan
every second sustained, which is far above what most teams produce.
If you have a fleet of CI runners hitting the same backend on the
same key, increase `SECURESCAN_RATE_LIMIT_PER_MIN` to match.

## Source

- Rate limit middleware:
  [`backend/securescan/middleware/rate_limit.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/middleware/rate_limit.py).
- Configuration:
  [`backend/securescan/config.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/config.py).

## Next

- [Configuration reference](../deployment/configuration.md) — full env-var list.
- [Production checklist](../deployment/production-checklist.md) — rate limits item.
