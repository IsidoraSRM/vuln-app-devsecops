from prometheus_client import Counter, Histogram, make_asgi_app

LOGIN_ATTEMPTS = Counter("login_attempts_total", "Total login attempts")
LOGIN_SUCCESS = Counter("login_success_total", "Total successful logins")
LOGIN_FAILURES = Counter("login_failures_total", "Total failed logins")
VULN_DETECTED = Counter("vulnerabilities_detected_total", "Total vulnerabilities detected")
SYNC_DURATION_MS = Histogram("sync_duration_ms", "Sync duration in ms")

metrics_app = make_asgi_app()
