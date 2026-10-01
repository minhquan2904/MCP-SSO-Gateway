#!/usr/bin/env bash
# Pre-push release scan for sensitive internal references.
#
#   scripts/release-scan.sh --self-test
#       Prove the scanner engine with generic canaries and prove gitleaks
#       reports the configured PAT rule for a runtime-generated synthetic token
#       while allowing documented fixtures. Requires gitleaks. When
#       MCP_GATEWAY_DENY_PATTERNS_FILE is set, also validate every deny
#       expression against its own canary.
#   MCP_GATEWAY_DENY_PATTERNS_FILE=/outside/repo/deny.tsv scripts/release-scan.sh
#       Full scan. Requires git, docker, gitleaks, and a locally built
#       mcp-sso-gateway:* release-candidate image.
#
# The deny file is supplied out-of-band (local file outside the repository or
# a protected CI secret) and is never committed. Each active line is
#   <python regular expression><TAB><synthetic sample that must match>
# Blank lines and lines starting with '#' are ignored. The canary column lets
# the scanner prove every expression matches without any pattern in the repo.
#
# Any match, malformed input, missing tool, or scanner error exits nonzero.
set -euo pipefail
cd "$(dirname -- "$0")/.."
exec python3 - "$@" <<'PY'
import base64
import hashlib
import json
import os
import pathlib
import re
import secrets
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path.cwd().resolve()
IMAGE_REPOSITORY = "mcp-sso-gateway"
ARTIFACT_DIRS = ("dist", "build", ".release-scan/artifacts")


class Finding(Exception):
    pass


def fail(message):
    print(f"release scan FAILED: {message}", file=sys.stderr)
    raise SystemExit(1)


def run(*args, input=None):
    try:
        result = subprocess.run(args, input=input, capture_output=True)
    except FileNotFoundError:
        fail(f"required tool not found: {args[0]}")
    if result.returncode:
        detail = result.stderr.decode("utf-8", "replace").strip()
        fail(f"{' '.join(args[:3])} exited {result.returncode}: {detail}")
    return result.stdout


def compile_deny_lines(lines):
    """Return compiled expressions; every expression must match its canary."""
    expressions = []
    for number, line in enumerate(lines, 1):
        if not line.strip() or line.startswith("#"):
            continue
        expression, tab, canary = line.partition("\t")
        if not tab or not expression or not canary:
            raise ValueError(f"line {number}: expected <regex><TAB><canary>")
        try:
            compiled = re.compile(expression)
        except re.error as error:
            raise ValueError(f"line {number}: invalid expression: {error}") from None
        if compiled.search(canary) is None:
            raise ValueError(f"line {number}: expression does not match its canary")
        if compiled.search("") is not None:
            raise ValueError(f"line {number}: expression matches empty input")
        expressions.append(compiled)
    if not expressions:
        raise ValueError("no active deny expressions")
    return expressions


def scan(expressions, label, data):
    # Decode losslessly so binary artifacts and non-UTF-8 history still scan.
    content = data.decode("utf-8", "surrogateescape")
    for number, expression in enumerate(expressions, 1):
        if expression.search(content):
            # Report location and expression index only; never echo patterns.
            raise Finding(f"deny expression #{number} matched {label}")


def load_deny_file(path):
    location = pathlib.Path(path).expanduser().resolve(strict=False)
    if location == ROOT or ROOT in location.parents:
        fail("deny file must live outside the repository so it cannot be committed")
    if not location.is_file():
        fail("MCP_GATEWAY_DENY_PATTERNS_FILE is not a readable regular file")
    try:
        lines = location.read_text(encoding="utf-8").splitlines()
        expressions = compile_deny_lines(lines)
    except (OSError, UnicodeDecodeError, ValueError) as error:
        fail(f"deny file rejected: {error}")
    print(f"release scan: {len(expressions)}/{len(expressions)} deny expressions matched their canaries")
    return expressions


def self_test_gitleaks():
    """Prove the configured PAT rule detects a valid-shaped token, not a fixture."""
    body = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    prefix = f"mcpgw_{body}"
    token = f"{prefix}_{hashlib.sha256(prefix.encode()).hexdigest()[:8]}"
    with tempfile.TemporaryDirectory(prefix="mcp-release-canary-") as directory:
        location = pathlib.Path(directory).resolve()
        if location == ROOT or ROOT in location.parents:
            fail("temporary canary directory must be outside the repository")
        sample = pathlib.Path(directory) / "input" / "sample"
        sample.parent.mkdir()
        report = pathlib.Path(directory) / "report.json"
        sample.write_text(token, encoding="ascii")
        command = ("gitleaks", "dir", "--config", str(ROOT / ".gitleaks.toml"),
                   "--redact", "--no-banner", "--exit-code", "1",
                   "--report-format", "json", "--report-path", str(report), str(sample.parent))
        try:
            result = subprocess.run(command, capture_output=True)
        except FileNotFoundError:
            fail("required tool not found: gitleaks")
        if result.returncode != 1:
            fail("gitleaks self-test did not detect the synthetic PAT")
        try:
            findings = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError):
            fail("gitleaks self-test did not produce a valid JSON report")
        if not isinstance(findings, list) or not any(
            isinstance(item, dict) and item.get("RuleID") == "mcp-gateway-personal-access-token"
            for item in findings
        ):
            fail("gitleaks self-test did not report the configured PAT rule")
        sample.write_text("password = 'alice-demo-password'\n", encoding="ascii")
        report.unlink()
        result = subprocess.run(command, capture_output=True)
        if result.returncode != 0:
            fail("gitleaks self-test rejected the allowlisted fixture or encountered an error")
    print("release scan self-test: gitleaks PAT rule detected synthetic token; allowlisted fixture clean")


def self_test():
    """Exercise the real engine end to end with generic, public canaries."""
    good = "release-scan-canary-[0-9]{4}\trelease-scan-canary-2468"
    expressions = compile_deny_lines([good, "# comment", ""])
    hits = [
        ("plain text", b"prefix release-scan-canary-1357 suffix"),
        ("binary bytes", b"\x00\xff release-scan-canary-9999 \xfe"),
        ("multi-line", b"line one\nrelease-scan-canary-0001\n"),
    ]
    for label, data in hits:
        try:
            scan(expressions, label, data)
        except Finding:
            print(f"release scan self-test: detected canary in {label}")
        else:
            fail(f"self-test missed canary in {label}")
    scan(expressions, "clean sample", b"release-scan-canary-abc and other public text")
    print("release scan self-test: clean sample produced no finding")
    rejected = {
        "canary mismatch": "release-scan-canary-[0-9]{4}\trelease-scan-canary-12",
        "missing canary": "release-scan-canary-[0-9]{4}",
        "invalid expression": "release-scan-canary-(\trelease-scan-canary-(",
        "empty match": "x*\txxx",
    }
    for label, line in rejected.items():
        try:
            compile_deny_lines([line])
        except ValueError:
            print(f"release scan self-test: rejected deny line with {label}")
        else:
            fail(f"self-test accepted deny line with {label}")
    try:
        compile_deny_lines(["# only comments", ""])
    except ValueError:
        print("release scan self-test: rejected deny file without active expressions")
    else:
        fail("self-test accepted an empty deny file")
    self_test_gitleaks()
    print("release scan self-test passed")


def check_boundaries():
    tracked = run("git", "ls-files", "--cached", "-z").split(b"\0")
    if any(path == b"private" or path.startswith(b"private/") for path in tracked):
        fail("private/ is tracked")
    for name in (".gitignore", ".dockerignore"):
        if "private/" not in pathlib.Path(name).read_text(encoding="utf-8").splitlines():
            fail(f"{name} must explicitly exclude private/")
    if "*" not in pathlib.Path(".dockerignore").read_text(encoding="utf-8").splitlines():
        fail(".dockerignore must allowlist the build context (start from '*')")


def publishable_paths():
    """Tracked plus untracked, non-ignored files: everything a commit could publish."""
    output = run("git", "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    paths = sorted({os.fsdecode(entry) for entry in output.split(b"\0") if entry})
    for path in paths:
        if path == "private" or path.startswith("private/"):
            fail("private/ content is publishable; fix ignore rules")
    return paths


def scan_working_tree(expressions, paths, mirror):
    count = 0
    for path in paths:
        entry = pathlib.Path(path)
        scan(expressions, f"path name {path}", os.fsencode(path))
        data = None
        if entry.is_symlink():
            data = os.fsencode(os.readlink(entry))
            scan(expressions, f"symlink target {path}", data)
        elif entry.is_file():
            data = entry.read_bytes()
            scan(expressions, f"working tree file {path}", data)
        elif entry.exists():
            fail(f"unsupported working-tree entry: {path}")
        if data is not None:
            target = mirror / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        # A tracked file deleted locally remains covered by the index scan.
        count += 1
    return count


def scan_index(expressions, mirror):
    """Scan staged blobs, including conflict stages and locally deleted paths."""
    listing = run("git", "ls-files", "--stage", "-z")
    by_oid = {}
    count = 0
    for entry in listing.split(b"\0"):
        if not entry:
            continue
        metadata, separator, raw_path = entry.partition(b"\t")
        fields = metadata.split()
        if not separator or not raw_path or len(fields) != 3:
            fail("malformed git index listing")
        mode, oid, stage = fields
        if mode not in (b"100644", b"100755", b"120000") or stage not in (b"0", b"1", b"2", b"3"):
            fail("unsupported git index mode or stage")
        path = os.fsdecode(raw_path)
        if path == "private" or path.startswith("private/"):
            fail("private/ is staged")
        scan(expressions, f"index path name {path}", raw_path)
        by_oid.setdefault(oid, []).append((stage, path, mode))
        count += 1
    if not by_oid:
        return 0
    ids = list(by_oid)
    batch = run("git", "cat-file", "--batch", input=b"\n".join(ids) + b"\n")
    offset = 0
    for oid in ids:
        end = batch.find(b"\n", offset)
        if end < 0:
            fail("malformed git index blob response")
        header = batch[offset:end].split(b" ")
        if len(header) != 3 or header[0] != oid or header[1] != b"blob" or not header[2].isdigit():
            fail("git index entry is not a readable blob")
        size = int(header[2])
        data = batch[end + 1 : end + 1 + size]
        offset = end + 1 + size + 1
        if len(data) != size or batch[offset - 1 : offset] != b"\n":
            fail("malformed git index blob response")
        for stage, path, mode in by_oid[oid]:
            kind = "symlink" if mode == b"120000" else "file"
            scan(expressions, f"index {kind} stage {stage.decode()} {path}", data)
            target = mirror / f"stage-{stage.decode()}" / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    if offset != len(batch):
        fail("git index blob response length mismatch")
    return count


def scan_artifacts(expressions):
    roots = [pathlib.Path(name) for name in ARTIFACT_DIRS]
    extra = os.environ.get("MCP_GATEWAY_RELEASE_ARTIFACTS_DIR")
    if extra:
        roots.append(pathlib.Path(extra))
        if not roots[-1].is_dir():
            fail("MCP_GATEWAY_RELEASE_ARTIFACTS_DIR is not a directory")
    count = 0
    for root in roots:
        if not root.exists():
            continue
        if root.is_symlink() or not root.is_dir():
            fail(f"artifact location must be a real directory: {root}")
        for base, dirs, files in os.walk(root, followlinks=False):
            for name in dirs + files:
                entry = pathlib.Path(base) / name
                scan(expressions, f"artifact name {entry}", os.fsencode(str(entry)))
                if entry.is_symlink():
                    scan(expressions, f"artifact symlink {entry}", os.fsencode(os.readlink(entry)))
                elif entry.is_file():
                    scan(expressions, f"artifact {entry}", entry.read_bytes())
                    count += 1
    return count


def tree_names(body, id_size):
    """Entries are '<mode> <name>\0<binary object id>'; return names only."""
    names, offset = [], 0
    while offset < len(body):
        space = body.index(b" ", offset)
        nul = body.index(b"\0", space)
        names.append(body[space + 1 : nul])
        offset = nul + 1 + id_size
    if offset != len(body):
        fail("malformed git tree object")
    return b"\n".join(names)


def scan_history(expressions):
    """Every reachable commit (metadata), tree (file names), tag, and blob."""
    refs = run("git", "for-each-ref", "--format=%(refname)")
    scan(expressions, "ref names", refs)
    listing = run("git", "rev-list", "--objects", "--all")
    ids = list(dict.fromkeys(line.split(b" ", 1)[0] for line in listing.splitlines() if line))
    if not ids:
        return 0
    batch = run("git", "cat-file", "--batch", input=b"\n".join(ids) + b"\n")
    offset = 0
    for oid in ids:
        end = batch.index(b"\n", offset)
        header = batch[offset:end].split(b" ")
        if len(header) != 3 or header[0] != oid:
            fail(f"unexpected git cat-file output for {oid.decode()}")
        kind, size = header[1].decode(), int(header[2])
        body = batch[end + 1 : end + 1 + size]
        offset = end + 1 + size + 1
        if kind == "tree":
            scan(expressions, f"tree {oid.decode()} file names", tree_names(body, len(oid) // 2))
        elif kind in ("commit", "tag", "blob"):
            scan(expressions, f"reachable {kind} {oid.decode()}", body)
        else:
            fail(f"unsupported git object type {kind}")
    if offset != len(batch):
        fail("git cat-file output length mismatch")
    return len(ids)


def scan_images(expressions):
    listing = run("docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}", IMAGE_REPOSITORY)
    images = sorted({line.decode() for line in listing.splitlines() if line and not line.endswith(b":<none>")})
    if not images:
        fail(f"no local {IMAGE_REPOSITORY}:* image; build the release candidate before scanning")
    for image in images:
        metadata = run("docker", "image", "inspect", "--format", "{{json .Config.Labels}}", image)
        scan(expressions, f"image labels {image}", metadata)
    return images


def run_gitleaks(tree_mirror, index_mirror):
    # Generic secrets: full reachable history plus separate mirrors of
    # publishable working-tree files and staged index blobs only, so ignored
    # local state (virtualenvs, private notes) is not scanned.
    run("gitleaks", "git", "--config", ".gitleaks.toml", "--log-opts=--all",
        "--redact", "--no-banner", "--exit-code", "1", ".")
    for mirror in (tree_mirror, index_mirror):
        run("gitleaks", "dir", "--config", str(ROOT / ".gitleaks.toml"),
            "--redact", "--no-banner", "--exit-code", "1", str(mirror))


def main(arguments):
    if run("git", "rev-parse", "--show-toplevel").decode().strip() != str(ROOT):
        fail("must run inside the repository root")
    supplied = os.environ.get("MCP_GATEWAY_DENY_PATTERNS_FILE", "")
    if arguments == ["--self-test"]:
        self_test()
        if supplied:
            load_deny_file(supplied)
        return
    if arguments:
        fail("usage: scripts/release-scan.sh [--self-test]")
    if not supplied:
        fail("MCP_GATEWAY_DENY_PATTERNS_FILE is required for the full release scan")
    self_test()
    expressions = load_deny_file(supplied)
    check_boundaries()
    scratch = pathlib.Path(tempfile.mkdtemp(prefix="mcp-release-scan-"))
    tree_mirror, index_mirror = scratch / "working-tree", scratch / "index"
    try:
        if scratch.resolve() == ROOT or ROOT in scratch.resolve().parents:
            fail("temporary scan mirrors must be outside the repository")
        tree_mirror.mkdir()
        index_mirror.mkdir()
        try:
            files = scan_working_tree(expressions, publishable_paths(), tree_mirror)
            staged = scan_index(expressions, index_mirror)
            artifacts = scan_artifacts(expressions)
            objects = scan_history(expressions)
            images = scan_images(expressions)
        except Finding as finding:
            fail(str(finding))
        run_gitleaks(tree_mirror, index_mirror)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    print(
        "release scan passed: "
        f"{files} publishable paths, {staged} index entries, {artifacts} artifacts, "
        f"{objects} reachable objects, images {', '.join(images)}; gitleaks clean"
    )


main(sys.argv[1:])
PY
