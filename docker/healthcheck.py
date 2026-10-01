"""Container health probe: the gateway answers /healthz on its internal port."""

from __future__ import annotations

from urllib.request import urlopen


def main() -> int:
    try:
        with urlopen("http://127.0.0.1:8000/healthz", timeout=2) as response:
            healthy = response.status == 200 and response.read() == b"ok"
    except OSError:
        return 1
    return 0 if healthy else 1


if __name__ == "__main__":
    raise SystemExit(main())
