## Summary

## Verification

- [ ] `uv sync --frozen`
- [ ] `uv run --frozen ruff check .`
- [ ] Socket-disabled pytest
- [ ] Generic Gitleaks, dependency audit, image build/scan, and Compose smoke in CI
- [ ] Out-of-band release scan, if this PR is release handoff

## Security boundary

- [ ] No secrets, live credentials, private hostnames, or deny patterns are committed.
- [ ] Production TLS, nginx-only ingress, private introspection, and upstream
      header trust assumptions remain documented and intact.
- [ ] Secret files stay service-scoped; gateway remains one SQLite worker.
- [ ] Docs claim only shipped v0.1 behavior (static YAML policy; PAT clients).

## Release

- [ ] No image publish, tag, or push is included without explicit release-owner approval.
