"""Command line of the instance dump: ``python -m dtvp.backup``.

Exit codes: 0 done (warnings go to standard error), 1 refused or failed,
2 usage error.
"""

import argparse
import json
import logging
import sys
from typing import Any, Sequence

from .errors import DumpError

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2


def _print_err(message: str) -> None:
    print(message, file=sys.stderr)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m dtvp.backup",
        description="Export, inspect and verify DTVP instance dumps (dtvp.dump/1).",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    export = commands.add_parser("export", help="write a dump of this instance")
    target = export.add_mutually_exclusive_group()
    target.add_argument("--out", help="output file, or - for standard output")
    target.add_argument("--dir", help="directory for a new, named dump file (default DTVP_BACKUP_PATH)")
    export.add_argument("--label", default="dtvp", help="file name prefix (default dtvp)")
    export.add_argument(
        "--include-access-tokens",
        action="store_true",
        help="include access-token digests; the dump then contains credentials",
    )
    export.add_argument("--without-source", action="store_true", help="leave out data read from Dependency-Track")
    export.add_argument("--tmp-dir", help="directory for the database snapshots")

    inspect = commands.add_parser("inspect", help="check the container and the manifest; print a summary")
    inspect.add_argument("file")
    inspect.add_argument("--json", action="store_true", help="print the summary as JSON")

    verify = commands.add_parser("verify", help="check every record of a dump")
    verify.add_argument("file")
    return parser


def _export(args: argparse.Namespace) -> int:
    from .export import export_dump

    if args.include_access_tokens:
        _print_err(
            "Warning: the dump will contain access-token digests. Anyone holding "
            "it can use those tokens against a DTVP with the same data; store and "
            "encrypt it as a credential."
        )
    result = export_dump(
        out=args.out,
        directory=args.dir,
        label=args.label,
        include_access_tokens=args.include_access_tokens,
        include_source=not args.without_source,
        tmp_dir=args.tmp_dir,
    )
    for warning in result.warnings:
        _print_err(f"Warning: {warning}")
    if result.path:
        print(result.path)
    return EXIT_OK


def _summary_text(summary: dict[str, Any]) -> str:
    lines = [
        f"Dump {summary['dump_id']} ({summary['format']})",
        f"Created {summary['created_at']} by {summary['created_by']} ({summary['reason']}), "
        f"DTVP {summary['dtvp']['version']} ({summary['dtvp']['build_commit']})",
        f"Dependency-Track: {summary['source']['dependency_track_url'] or 'unknown'}",
        f"Contains credentials: {'yes' if summary['contains_credentials'] else 'no'}",
        f"Excluded: {', '.join(summary['excluded']) or 'nothing'}",
        "Records:",
        *(f"  {name}: {count}" for name, count in summary["records"].items()),
        "Settings files:",
        *(f"  {name}: {state}" for name, state in summary["config"].items()),
    ]
    return "\n".join(lines)


def _inspect(args: argparse.Namespace) -> int:
    from .verify import inspect_dump

    summary = inspect_dump(args.file)
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(_summary_text(summary))
    for warning in summary["warnings"]:
        _print_err(f"Warning: {warning}")
    return EXIT_OK


def _verify(args: argparse.Namespace) -> int:
    from .verify import verify_dump

    result = verify_dump(args.file)
    for warning in result.warnings:
        _print_err(f"Warning: {warning}")
    if result.errors:
        for error in result.errors:
            _print_err(f"Refused: {error}")
        return EXIT_FAILED
    print(
        f"OK: dump {result.manifest['dump_id']}, "
        f"{sum(result.records.values())} records"
    )
    return EXIT_OK


COMMANDS = {"export": _export, "inspect": _inspect, "verify": _verify}


def main(argv: Sequence[str] | None = None) -> int:
    log = logging.getLogger("dtvp.backup")
    if not log.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(message)s"))
        log.addHandler(handler)
        log.setLevel(logging.INFO)
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return EXIT_USAGE if exc.code not in (0, None) else EXIT_OK
    try:
        return COMMANDS[args.command](args)
    except DumpError as exc:
        _print_err(f"Refused: {exc}")
        return EXIT_FAILED
    except (OSError, ValueError) as exc:
        _print_err(f"Failed: {exc}")
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
