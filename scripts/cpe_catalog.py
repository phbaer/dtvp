"""Explicit operator catalog capture, verification, rebuild and bounded search."""

import argparse
import json
import sys
from pathlib import Path


def main():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from dtvp.knowledge.cpe_catalog import Catalog, demo_catalog

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, required=True, help="Installation artifact_dir/cpe-catalog"
    )
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser(
        "demo", help="Create a clearly synthetic offline catalog; requires no selected generation"
    )
    intake = actions.add_parser(
        "import", help="Validate and activate a complete NVD tar.gz + META capture"
    )
    intake.add_argument("--archive", type=Path, required=True)
    intake.add_argument("--meta", type=Path, required=True)
    for action in ("verify", "rebuild"):
        verify = actions.add_parser(action)
        verify.add_argument("--generation")
    actions.add_parser(
        "mirror", help="Explicitly check official META and acquire a changed complete archive"
    )
    search = actions.add_parser("search")
    search.add_argument("query")
    search.add_argument("--generation")
    search.add_argument("--offset", type=int, default=0)
    search.add_argument("--limit", type=int, default=50)
    search.add_argument("--include-deprecated", action="store_true")
    export = actions.add_parser(
        "export", help="Write one explicit result page for curated dictionary intake"
    )
    export.add_argument("query")
    export.add_argument("--generation")
    export.add_argument("--offset", type=int, default=0)
    export.add_argument("--limit", type=int, default=50)
    export.add_argument("--include-deprecated", action="store_true")
    export.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    catalog = Catalog(args.root)
    if args.action == "demo":
        result = demo_catalog(args.root)
    elif args.action == "import":
        result = catalog.import_archive(args.archive, args.meta)
    elif args.action == "mirror":
        result = catalog.mirror()
    elif args.action in {"verify", "rebuild"}:
        result = catalog.verify(args.generation, rebuild=args.action == "rebuild")
    elif args.action == "export":
        from dtvp.storage import canonical

        result = catalog.export(
            args.query,
            generation=args.generation,
            offset=args.offset,
            limit=args.limit,
            include_deprecated=args.include_deprecated,
        )
        with args.output.open("xb") as output:
            output.write(canonical(result.pop("dictionary")))
        result.pop("content_base64", None)
    else:
        result = catalog.search(
            args.query,
            generation=args.generation,
            offset=args.offset,
            limit=args.limit,
            include_deprecated=args.include_deprecated,
        )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
