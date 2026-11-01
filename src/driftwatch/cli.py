"""The ``driftwatch`` command line."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from driftwatch import __version__


def _print(obj: object) -> None:
    print(json.dumps(obj, indent=2, default=str))


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from driftwatch.server.app import create_app

    uvicorn.run(create_app(), host=args.host, port=args.port, proxy_headers=False, log_level="info")
    return 0


def cmd_mock_edr(args: argparse.Namespace) -> int:
    import uvicorn

    from driftwatch.mock_edr.app import create_app

    uvicorn.run(create_app(), host=args.host, port=args.port, log_level="info")
    return 0


def cmd_pki_init(args: argparse.Namespace) -> int:
    from driftwatch.crypto import Signer, init_pki

    paths = init_pki(Path(args.dir), [h.strip() for h in args.hosts.split(",") if h.strip()])
    signer = Signer.load(paths["signing_key"])
    print(f"PKI ready in {args.dir}")
    print(f"Bundle signing public key (pin this in every agent config): {signer.public_key_b64()}")
    return 0


def cmd_schema(args: argparse.Namespace) -> int:
    from driftwatch.schema import export_json_schema

    text = json.dumps(export_json_schema(), indent=2) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(text)
    return 0


def cmd_catalog(_: argparse.Namespace) -> int:
    from driftwatch.catalog import catalog_as_dicts

    _print(catalog_as_dicts())
    return 0


def _library(args: argparse.Namespace):
    from driftwatch.library import Library

    return Library(*[Path(d) for d in args.dirs])


def cmd_library_validate(args: argparse.Namespace) -> int:
    from driftwatch.library import LibraryError

    try:
        lib = _library(args)
    except LibraryError as exc:
        print(f"invalid: {exc}", file=sys.stderr)
        return 1
    print(f"{len(lib)} tests valid")
    return 0


def cmd_library_list(args: argparse.Namespace) -> int:
    for t in _library(args).all():
        print(f"{t.id:40} {t.status.value:9} {','.join(t.platforms):14} {','.join(t.attack.techniques)}")
    return 0


def cmd_library_approve(args: argparse.Namespace) -> int:
    from driftwatch.library import LibraryError, approve

    lib = _library(args)
    try:
        approved = approve(lib.get(args.test_id), args.reviewer, args.notes)
    except LibraryError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    path = lib.path_of(args.test_id)
    if args.move_to and path.parent.resolve() != Path(args.move_to).resolve():
        target = Path(args.move_to) / path.name
        lib.save(approved, target)
        path.unlink()
        path = target
    else:
        lib.save(approved)
    print(f"{args.test_id} approved by {args.reviewer}; written to {path}. It becomes verified after a clean lab run.")
    return 0


def cmd_rules_lint(args: argparse.Namespace) -> int:
    from driftwatch.sigma import SigmaError, load_rules, to_kql

    try:
        rules = load_rules(Path(args.rules))
        for rule in rules.values():
            to_kql(rule)
    except SigmaError as exc:
        print(f"invalid: {exc}", file=sys.stderr)
        return 1
    print(f"{len(rules)} rules valid and convertible to KQL")
    return 0


def cmd_rules_kql(args: argparse.Namespace) -> int:
    from driftwatch.sigma import load_rules, to_kql

    for rule in load_rules(Path(args.rules)).values():
        if args.id in (None, rule.id):
            print(f"# {rule.title} ({rule.id})\n{to_kql(rule)}\n")
    return 0


def cmd_rules_deploy(args: argparse.Namespace) -> int:
    from driftwatch.sigma import load_rules
    from driftwatch.sigma.kibana import deploy

    results = deploy(list(load_rules(Path(args.rules)).values()), args.kibana, args.index.split(","),
                     user=os.environ.get("DRIFTWATCH_KIBANA_USER"),
                     password=os.environ.get("DRIFTWATCH_KIBANA_PASSWORD"),
                     api_key=os.environ.get("DRIFTWATCH_KIBANA_API_KEY"),
                     verify=os.environ.get("DRIFTWATCH_KIBANA_CA", True))
    _print(results)
    return 0 if all(r["ok"] for r in results) else 1


def _changed_files(args: argparse.Namespace) -> list[str] | None:
    if args.changed_files:
        return [line.strip() for line in Path(args.changed_files).read_text().splitlines() if line.strip()]
    if args.base_ref:
        out = subprocess.run(["git", "diff", "--name-only", f"{args.base_ref}...HEAD"],  # noqa: S603, S607
                             check=True, capture_output=True, text=True).stdout
        return [line.strip() for line in out.splitlines() if line.strip()]
    return None


def cmd_regress(args: argparse.Namespace) -> int:
    from driftwatch.library import Library
    from driftwatch.regression import run_live, run_offline, to_junit, to_markdown

    library = Library(*[Path(d) for d in args.dirs])
    changed = _changed_files(args)
    report = run_offline(Path(args.rules), library, Path(args.telemetry), changed, args.require_coverage)
    if args.live:
        api_key = os.environ.get("DRIFTWATCH_ADMIN_TOKEN", "")
        if not (args.server and api_key):
            print("--live needs --server and DRIFTWATCH_ADMIN_TOKEN", file=sys.stderr)
            return 2
        report = run_live(report, args.server, api_key, args.tags.split(","),
                          verify=os.environ.get("DRIFTWATCH_CA_CERT", True))
    if args.junit:
        Path(args.junit).write_text(to_junit(report), encoding="utf-8")
    markdown = to_markdown(report)
    if args.markdown:
        Path(args.markdown).write_text(markdown, encoding="utf-8")
    print(markdown)
    return 0 if report.ok else 1


def cmd_evidence_verify(args: argparse.Namespace) -> int:
    from driftwatch.results.evidence import EvidenceError, verify_bundle

    try:
        manifest = verify_bundle(Path(args.bundle).read_bytes(), Path(args.public_key).read_text().strip())
    except EvidenceError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    print(f"valid: run {manifest['run_id']} of {manifest['test']['id']} on {manifest['agent']['hostname']}: "
          f"{manifest['outcome']} ({'pass' if manifest['passed'] else 'fail'})")
    return 0


def cmd_intel_latest(args: argparse.Namespace) -> int:
    from driftwatch.intel.cisa import CisaClient

    client = CisaClient()
    try:
        _print(client.latest(args.feed, args.limit))
    finally:
        client.close()
    return 0


def cmd_intel_draft(args: argparse.Namespace) -> int:
    from driftwatch.intel.cisa import CisaClient, parse_advisory
    from driftwatch.intel.drafter import claude_drafts, offline_drafts, write_drafts
    from driftwatch.library import Library

    if args.html:
        advisory = parse_advisory(Path(args.html).read_text(encoding="utf-8"), args.url)
    else:
        client = CisaClient()
        try:
            advisory = client.advisory(args.url)
        finally:
            client.close()
    print(f"{advisory.id or 'advisory'}: {advisory.title}: techniques {', '.join(advisory.technique_ids) or 'none'}")
    use_claude = not args.offline and (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))
    if use_claude:
        import anthropic

        result = claude_drafts(advisory, anthropic.Anthropic(), args.model)
    else:
        result = offline_drafts(advisory)
    library = Library(*[Path(d) for d in args.dirs])
    written = write_drafts(result, Path(args.out), {t.id for t in library.all()})
    _print({"generator": result.generator, "written": [str(p) for p in written], "rejected": result.rejected,
            "unsupported_techniques": result.unsupported_techniques, "notes": result.notes})
    return 0


def cmd_demo_seed(args: argparse.Namespace) -> int:
    from driftwatch.demo import seed
    from driftwatch.library import Library
    from driftwatch.server.store import Store

    store = Store(Path(args.db))
    counts = seed(store, Library(*[Path(d) for d in args.dirs]), days=args.days)
    store.close()
    print(f"seeded {args.db}: {counts}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="driftwatch", description="Continuous security validation for a lab")
    p.add_argument("--version", action="version", version=f"driftwatch {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    dirs_default = ["library/tests", "library/drafts"]

    s = sub.add_parser("serve", help="run the control server")
    s.add_argument("--host", default="0.0.0.0")  # noqa: S104 - listens inside the compose network behind nginx
    s.add_argument("--port", type=int, default=8000)
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("mock-edr", help="run the mock Defender / CrowdStrike APIs")
    s.add_argument("--host", default="0.0.0.0")  # noqa: S104
    s.add_argument("--port", type=int, default=8080)
    s.set_defaults(func=cmd_mock_edr)

    s = sub.add_parser("pki", help="certificate authority and signing key")
    pki = s.add_subparsers(dest="pki_command", required=True)
    s = pki.add_parser("init", help="create the CA, server certificate and bundle signing key")
    s.add_argument("--dir", default="deploy/pki")
    s.add_argument("--hosts", default="driftwatch.lab,localhost,127.0.0.1")
    s.set_defaults(func=cmd_pki_init)

    s = sub.add_parser("schema", help="export the test YAML JSON Schema")
    s.add_argument("--out")
    s.set_defaults(func=cmd_schema)

    s = sub.add_parser("catalog", help="print the Safe Action Catalog")
    s.set_defaults(func=cmd_catalog)

    s = sub.add_parser("library", help="validate, list and approve tests")
    lib = s.add_subparsers(dest="library_command", required=True)
    for name, func in (("validate", cmd_library_validate), ("list", cmd_library_list)):
        s = lib.add_parser(name)
        s.add_argument("--dirs", nargs="+", default=dirs_default)
        s.set_defaults(func=func)
    s = lib.add_parser("approve", help="human review gate: draft -> approved")
    s.add_argument("test_id")
    s.add_argument("--reviewer", required=True)
    s.add_argument("--notes")
    s.add_argument("--move-to", default="library/tests", help="move the approved file out of drafts")
    s.add_argument("--dirs", nargs="+", default=dirs_default)
    s.set_defaults(func=cmd_library_approve)

    s = sub.add_parser("rules", help="Sigma rule tools")
    rules = s.add_subparsers(dest="rules_command", required=True)
    s = rules.add_parser("lint")
    s.add_argument("--rules", default="rules")
    s.set_defaults(func=cmd_rules_lint)
    s = rules.add_parser("kql", help="print rules as Kibana KQL")
    s.add_argument("--rules", default="rules")
    s.add_argument("--id")
    s.set_defaults(func=cmd_rules_kql)
    s = rules.add_parser("deploy", help="create or update the rules in the Kibana detection engine")
    s.add_argument("--rules", default="rules")
    s.add_argument("--kibana", required=True)
    s.add_argument("--index", default="logs-*")
    s.set_defaults(func=cmd_rules_deploy)

    s = sub.add_parser("regress", help="detection regression gate (CI)")
    s.add_argument("--rules", default="rules")
    s.add_argument("--telemetry", default="telemetry")
    s.add_argument("--dirs", nargs="+", default=["library/tests"])
    s.add_argument("--changed-files", help="file listing changed paths, one per line")
    s.add_argument("--base-ref", help="git ref to diff against, e.g. origin/main")
    s.add_argument("--require-coverage", action="store_true")
    s.add_argument("--junit")
    s.add_argument("--markdown")
    s.add_argument("--live", action="store_true", help="also run the tests on lab agents via the server")
    s.add_argument("--server")
    s.add_argument("--tags", default="lab")
    s.set_defaults(func=cmd_regress)

    s = sub.add_parser("evidence", help="evidence bundle tools")
    ev = s.add_subparsers(dest="evidence_command", required=True)
    s = ev.add_parser("verify")
    s.add_argument("bundle")
    s.add_argument("--public-key", required=True, help="bundle-signing.pub from the server's PKI folder")
    s.set_defaults(func=cmd_evidence_verify)

    s = sub.add_parser("intel", help="CISA advisories and AI-assisted drafting")
    intel = s.add_subparsers(dest="intel_command", required=True)
    s = intel.add_parser("latest")
    s.add_argument("--feed", default="https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml")
    s.add_argument("--limit", type=int, default=10)
    s.set_defaults(func=cmd_intel_latest)
    s = intel.add_parser("draft", help="draft tests from one advisory")
    s.add_argument("url")
    s.add_argument("--html", help="read the advisory from a saved HTML file instead of fetching it")
    s.add_argument("--offline", action="store_true", help="never call Claude; use the deterministic mapper")
    s.add_argument("--model", default="claude-opus-5-5")
    s.add_argument("--out", default="library/drafts")
    s.add_argument("--dirs", nargs="+", default=dirs_default)
    s.set_defaults(func=cmd_intel_draft)

    s = sub.add_parser("demo", help="demo data")
    demo = s.add_subparsers(dest="demo_command", required=True)
    s = demo.add_parser("seed", help="fill a database with a synthetic week of lab activity")
    s.add_argument("--db", default="data/driftwatch.sqlite3")
    s.add_argument("--days", type=int, default=7)
    s.add_argument("--dirs", nargs="+", default=dirs_default)
    s.set_defaults(func=cmd_demo_seed)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
