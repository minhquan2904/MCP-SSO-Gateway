"""Token administration CLI: `mcp-gateway issue|revoke|list`.

Plaintext tokens are printed exactly once, to stdout. `issue` refuses an
identity that has no allowed server in the static policy.
"""

from __future__ import annotations

import argparse
import sys

from .config import load_config
from .policy.base import Decision
from .policy.static_yaml import StaticYamlPolicy
from .registry import load_registry
from .tokens import Identity, TokenStore


def _build(environ=None):
    cfg = load_config(environ)
    registry = load_registry(
        cfg.registry_file,
        secrets_dir=cfg.secrets_dir,
        reserved_secret_files=cfg.reserved_secret_files,
    )
    policy = StaticYamlPolicy(cfg.policy_file, registry)
    store = TokenStore(cfg.db_path)
    return cfg, registry, policy, store


def _identity(issuer: str, subject: str) -> Identity:
    from .tokens import make_identity

    return make_identity(issuer, subject)


def cmd_issue(args: argparse.Namespace) -> int:
    cfg, registry, policy, store = _build(args.environ)
    identity = _identity(args.issuer, args.subject)
    allowed = [
        entry.name
        for entry in registry
        if policy.check(identity.issuer, identity.subject, entry.name) is Decision.ALLOW
    ]
    if not allowed:
        print(
            f"error: identity {identity.identity_id} is not granted any registered server; "
            "the policy must allow this issuer and subject before a token can be issued",
            file=sys.stderr,
        )
        return 1
    issued = store.issue(
        identity.issuer, identity.subject, args.label, cfg.token_ttl_days * 86400,
        replace=args.replace,
    )
    print(f"identity: {issued.identity_id}")
    print(f"label:    {issued.label}")
    print(f"expires:  {issued.expires_at}")
    print(f"token:    {issued.token}")
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    _, _, _, store = _build(args.environ)
    identity = _identity(args.issuer, args.subject)
    count = store.revoke(identity.issuer, identity.subject, args.label)
    print(f"revoked {count} token(s) with label {args.label!r}")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    _, _, _, store = _build(args.environ)
    identity = _identity(args.issuer, args.subject)
    rows = store.list_active(identity.issuer, identity.subject)
    if not rows:
        print("no active tokens")
        return 0
    for row in rows:
        last_used = str(row.last_used_at) if row.last_used_at is not None else "never"
        print(f"{row.label}\tcreated={row.created_at}\tlast_used={last_used}\texpires={row.expires_at}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-gateway", description="MCP SSO Gateway token administration"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_identity_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--issuer", required=True)
        p.add_argument("--subject", required=True)

    issue = sub.add_parser("issue", help="issue a personal token")
    add_identity_args(issue)
    issue.add_argument("--label", required=True)
    issue.add_argument("--replace", action="store_true")
    issue.set_defaults(func=cmd_issue, environ=None)

    revoke = sub.add_parser("revoke", help="revoke tokens by label")
    add_identity_args(revoke)
    revoke.add_argument("--label", required=True)
    revoke.set_defaults(func=cmd_revoke, environ=None)

    list_cmd = sub.add_parser("list", help="list active tokens for an identity")
    add_identity_args(list_cmd)
    list_cmd.set_defaults(func=cmd_list, environ=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
