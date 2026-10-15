import argparse

import uvicorn
from sqlalchemy import select

from dtvp.config import Settings
from dtvp.db import engine_for, migrate, sessions
from dtvp.jobs import run
from dtvp.models import User
from dtvp.storage import Artifacts


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    sub.add_parser("worker")
    sub.add_parser("migrate")
    sub.add_parser("rebuild-knowledge", help="Rebuild only v3 projections from the local journal")
    bootstrap = sub.add_parser("bootstrap")
    bootstrap.add_argument("--issuer", required=True)
    bootstrap.add_argument("--subject", required=True)
    bootstrap.add_argument("--name", required=True)
    args = parser.parse_args()
    if args.command == "serve":
        uvicorn.run("dtvp.main:create_app", factory=True, host=args.host, port=args.port)
        return
    settings = Settings()
    engine = engine_for(settings.database_url)
    migration_engine = engine_for(settings.migration_database_url or settings.database_url)
    migrate(migration_engine, settings.artifact_dir.parent / "migration-backups")
    migration_engine.dispose()
    factory = sessions(engine)
    if args.command == "rebuild-knowledge":
        import json

        from dtvp.knowledge.journal import Journal
        from dtvp.knowledge.projection import catch_up

        print(
            json.dumps(catch_up(engine, Journal(settings.artifact_dir / "knowledge"), rebuild=True))
        )
    elif args.command == "worker":
        run(factory, Artifacts(settings.artifact_dir), settings)
    elif args.command == "bootstrap":
        with factory.begin() as db:
            user = db.scalar(
                select(User).where(User.issuer == args.issuer, User.subject == args.subject)
            )
            if not user:
                user = User(issuer=args.issuer, subject=args.subject, name=args.name)
                db.add(user)
            user.org_admin = True
        print("Organization administrator registered; sign in with the matching OIDC identity.")
    engine.dispose()


if __name__ == "__main__":
    main()
