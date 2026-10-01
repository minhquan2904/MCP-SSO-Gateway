.PHONY: test lint smoke build release-scan release-scan-selftest

test:
	uv run pytest

lint:
	uv run ruff check .

smoke:
	bash scripts/smoke-test.sh

build:
	docker build -t mcp-sso-gateway:local .

release-scan:
	scripts/release-scan.sh

release-scan-selftest:
	scripts/release-scan.sh --self-test
