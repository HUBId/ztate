# SDK rate limit handling

The RPC returns standard HTTP rate-limit headers when a request is throttled.
Clients should use the values to throttle themselves instead of hammering the
server with blind retries. The helpers exported by `rpp-chain-cli` mirror the
server semantics so SDKs can share the same backoff behavior.

## Inspect the headers

Use `rate_limit_window` to read the limit, the remaining budget, and the reset
interval expressed in seconds until a token becomes available again.

```rust
use std::time::Duration;
use reqwest::header::{HeaderMap, HeaderValue};
use rpp_chain_cli::rate_limit::rate_limit_window;

let mut headers = HeaderMap::new();
headers.insert("X-RateLimit-Limit", HeaderValue::from_static("120"));
headers.insert("X-RateLimit-Remaining", HeaderValue::from_static("0"));
headers.insert("X-RateLimit-Reset", HeaderValue::from_static("1"));

let window = rate_limit_window(&headers, Duration::from_millis(25));
assert_eq!(window.limit, Some(120));
assert_eq!(window.remaining, Some(0));
assert_eq!(window.reset_after, Duration::from_secs(1));
```

## Back off before retrying

The `compute_retry_delay` helper prioritizes `X-RateLimit-Reset` and falls back
to `Retry-After` so clients match the server’s token-bucket semantics. The
returned delay is clamped to a caller-provided floor to avoid tight loops even
when a proxy strips headers.

```rust
use std::time::Duration;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::StatusCode;
use rpp_chain_cli::rate_limit::{compute_retry_delay, rate_limit_window};
use tokio::runtime::Runtime;
use tokio::time::sleep;

let mut headers = HeaderMap::new();
headers.insert("X-RateLimit-Reset", HeaderValue::from_static("0"));
headers.insert("Retry-After", HeaderValue::from_static("2"));

let rt = Runtime::new().unwrap();
rt.block_on(async {
    let window = rate_limit_window(&headers, Duration::from_millis(20));
    let delay = compute_retry_delay(StatusCode::TOO_MANY_REQUESTS, &headers, Duration::from_millis(20));

    // Respect the advertised window before sending the next request.
    sleep(delay).await;

    // Your retry goes here; the example just checks the delay.
    assert!(delay >= window.reset_after);
});
```

## Snapshot RPC error mapping

Use `classify_snapshot_error` to convert snapshot RPC responses into a typed
`SnapshotError`. The helper understands the state-sync error codes described in
`docs/interfaces/rpc/README.md` and backoffs according to rate-limit headers so
callers can retry transient verifier failures without guessing delay windows.

## Mobile and embedded SDK smoke coverage

The CI job `wallet-sdk-mobile-embedded` exercises the minimal RPC surface that
mobile and embedded SDKs rely on—auth negotiation, rate-limit headers, and the
wallet signing error contract. The job runs `cargo test --locked --test
sdk_mobile_embedded_smoke --features "wallet-integration"` against a local test
node shim and uploads `logs/sdk-smoke/*.log` if the flow fails, giving SDK
maintainers an artifact trail when throttling or auth regressions occur.

To reproduce the same coverage locally:

1. `cargo test --locked --test sdk_mobile_embedded_smoke --features "wallet-integration" -- --nocapture`
2. Inspect `logs/sdk-smoke/mobile.log` and `logs/sdk-smoke/embedded.log` for the
   echoed payloads, rate-limit windows, and the signing error emitted by the
   server harness.
3. Toggle the `AUTH_TOKEN` constant in `tests/sdk_mobile_embedded_smoke.rs` if
   you want to validate client behavior against alternate bearer tokens.

## Reconnect and replay after node restarts

Long-lived clients should assume occasional consensus restarts and keep their
subscriptions or polling loops alive without dropping user-visible state. Use a
monotonic retry strategy across transports:

* **SSE/WebSocket subscribers** – reuse the last durable cursor or sequence
  number when reconnecting, emit a short exponential backoff (`250 ms`,
  `500 ms`, `1 s`, capped at `5 s`), and log every reconnect attempt. Treat a
  reset connection during leadership changes as informational; only surface an
  error after three consecutive failures within five minutes.
* **Polling JSON-RPC clients** – treat `ECONNRESET`, `ECONNREFUSED`, and `503`
  errors as transient while a node comes back. Retry the same request payload
  after an exponential backoff capped at `5 s` instead of rebuilding higher
  layers like wallet caches. Keep the last successful response around so UI
  components can render stale-but-correct values during the reconnect window.

The `rpc_sdk_reconnect` integration test exercises these behaviors for the Rust
(`rpp_wallet::rpc::client`), Go (HTTP poller), and TypeScript (Node fetch)
clients while restarting consensus nodes. When it fails, inspect the captured
artifacts under `logs/sdk-reconnect/` before retrying locally.
