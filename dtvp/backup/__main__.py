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
        description="Export, inspect, verify and restore River instance dumps (dtvp.dump/1).",
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
    verify.add_argument(
        "--deep",
        action="store_true",
        help="also stage the dump in a temporary directory and prove the round trip",
    )

    restore = commands.add_parser(
        "restore", help="restore a dump into this instance; the backend must be stopped"
    )
    restore.add_argument("file")
    restore.add_argument("--dry-run", action="store_true", help="check and report; change nothing")
    restore.add_argument("--replace", action="store_true", help="move the target's records aside")
    restore.add_argument("--new-instance", action="store_true", help="no backend has run here yet")
    restore.add_argument("--accept-dt-url-change", action="store_true")
    restore.add_argument("--accept-pruning", action="store_true")
    restore.add_argument("--accept-path-change", action="store_true")
    restore.add_argument(
        "--allow-unknown",
        action="store_true",
        help="drop entities and fields of a newer minor format version",
    )

    prune = commands.add_parser("prune", help="delete the oldest dumps in a directory")
    prune.add_argument("dir")
    prune.add_argument("--keep", type=int, required=True, help="how many dumps to keep (at least 1)")
    prune.add_argument("--label", default="dtvp", help="only dumps with this label (default dtvp)")

    recover = commands.add_parser("recover", help="complete or undo an interrupted restore")
    mode = recover.add_mutually_exclusive_group(required=True)
    mode.add_argument("--resume", action="store_true")
    mode.add_argument("--abort", action="store_true")
    return parser


def _export(args: argparse.Namespace) -> int:
    from .export import export_dump

    if args.include_access_tokens:
        _print_err(
            "Warning: the dump will contain access-token digests. Anyone holding "
            "it can use those tokens against a River with the same data; store and "
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
        f"River {summary['dtvp']['version']} ({summary['dtvp']['build_commit']})",
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

    if args.deep:
        from .restore import verify_deep

        deep = verify_deep(args.file)
        for warning in deep["warnings"]:
            _print_err(f"Warning: {warning}")
        print(
            f"OK: dump {deep['dump_id']}, {sum(deep['records'].values())} records, "
            "staged and read back identically"
        )
        return EXIT_OK
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


def _restore(args: argparse.Namespace) -> int:
    from .restore import RestoreOptions, restore_dump

    options = RestoreOptions(
        replace=args.replace,
        new_instance=args.new_instance,
        accept_dt_url_change=args.accept_dt_url_change,
        accept_pruning=args.accept_pruning,
        accept_path_change=args.accept_path_change,
        allow_unknown=args.allow_unknown,
    )
    result = restore_dump(args.file, options=options, dry_run=args.dry_run)
    for warning in result.warnings:
        _print_err(f"Warning: {warning}")
    if result.dry_run:
        print(f"Dry run of dump {result.dump_id}; nothing was changed.")
        print(f"Instance lock currently held: {'yes' if result.lock_held else 'no'}")
        print("Planned actions:")
        for action in result.actions:
            if not action["original_existed"] and not action["staged"]:
                continue
            steps = []
            if action["original_existed"]:
                steps.append(f"move {action['target']} to {action['aside']}")
            if action["staged"]:
                steps.append(f"put the restored file at {action['target']}")
            print("  " + "; ".join(steps))
        for refusal in result.refusals:
            _print_err(f"Refused: {refusal}")
        return EXIT_FAILED if result.refusals else EXIT_OK
    print(f"Restored dump {result.dump_id}: {sum(result.records.values())} records.")
    print(
        "The replaced files are kept as *.pre-restore-" + result.run_id + "; remove "
        "them once the restored instance is checked."
    )
    print(
        "Note: browser sessions stay valid only if DTVP_SESSION_SECRET_KEY is the "
        "same as on the source; access tokens exist only if the dump included them."
    )
    return EXIT_OK


def _recover(args: argparse.Namespace) -> int:
    from .restore import recover

    outcome = recover("resume" if args.resume else "abort")
    verb = "completed" if args.resume else "undone"
    print(f"Restore of dump {outcome['dump_id']} {verb}.")
    return EXIT_OK


def _prune(args: argparse.Namespace) -> int:
    from .schedule import prune_dumps

    if args.keep < 1:
        _print_err("--keep must be at least 1")
        return EXIT_USAGE
    for path in prune_dumps(args.dir, args.keep, label=args.label):
        print(f"Removed {path}")
    return EXIT_OK


COMMANDS = {
    "prune": _prune,
    "export": _export,
    "inspect": _inspect,
    "verify": _verify,
    "restore": _restore,
    "recover": _recover,
}


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
