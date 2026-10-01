"""Local administration and the single-process server."""

from __future__ import annotations

import argparse
import sys

import uvicorn

from open_did_server.app import create_app
from open_did_server.config import load_settings
from open_did_server.errors import ApiError
from open_did_server.service import Service
from open_did_server.store import Store


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="open-did-server")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Create the local database and high-water file")

    create = sub.add_parser("create-grant", help="Create a publication grant and print its token once")
    create.add_argument("--owner", required=True)
    create.add_argument("--wba-path", action="append", default=[])
    create.add_argument("--web-path", action="append", default=[])
    create.add_argument("--wba-root", action="store_true")
    create.add_argument("--web-root", action="store_true")
    create.add_argument("--handle", action="append", default=[])
    create.add_argument("--expires-at", type=int)

    revoke = sub.add_parser("revoke-grant", help="Revoke a publication grant")
    revoke.add_argument("--grant-id", required=True)

    status = sub.add_parser("set-auth-status", help="Set local DID authentication status")
    status.add_argument("--did", required=True)
    status.add_argument("--status", required=True, choices=["active", "suspended"])

    mark = sub.add_parser("mark-maintenance", help="Stop name and authentication writes")
    mark.add_argument("--reason", default="operator maintenance")
    sub.add_parser("clear-maintenance", help="Resume service after the signature window and high-water check")
    sub.add_parser("serve", help="Listen for HTTP requests")

    args = parser.parse_args(argv)
    try:
        settings = load_settings()
        if args.command == "serve":
            _serve(settings)
            return
        service = Service(settings, Store(settings.database_path))
        # Serving is the only command that may slide an existing replay deadline.
        service.startup(extend_replay=False)
        if args.command == "init":
            print(f"initialized {settings.database_path}")
        elif args.command == "create-grant":
            wba_paths = list(args.wba_path)
            web_paths = list(args.web_path)
            if args.wba_root:
                wba_paths.append("")
            if args.web_root:
                web_paths.append("")
            grant_id, token = service.create_grant(
                args.owner,
                wba_paths=wba_paths,
                web_paths=web_paths,
                handles=list(args.handle),
                expires_at=args.expires_at,
            )
            print(f"grant_id={grant_id}")
            print(f"owner_id={args.owner}")
            print(f"token={token}")
        elif args.command == "revoke-grant":
            service.revoke_grant(args.grant_id)
            print(f"revoked {args.grant_id}")
        elif args.command == "set-auth-status":
            count = service.set_auth_status(args.did, args.status)
            print(f"did={args.did}")
            print(f"status={args.status}")
            print(f"handles_suspended={count}")
        elif args.command == "mark-maintenance":
            service.mark_maintenance(args.reason)
            print("maintenance=1")
        elif args.command == "clear-maintenance":
            service.clear_maintenance()
            print("maintenance=0")
    except (ApiError, ValueError) as exc:
        message = exc.message if isinstance(exc, ApiError) else str(exc)
        print(message, file=sys.stderr)
        raise SystemExit(1) from exc


def _serve(settings) -> None:
    app = create_app(settings)
    reason = app.state.service.startup()
    if reason:
        print(f"maintenance: {reason}", file=sys.stderr)

    class _ReadyServer(uvicorn.Server):
        async def startup(self, sockets=None) -> None:
            await super().startup(sockets)
            print(
                f"Open DID Server listening on http://{settings.host}:{settings.port}",
                flush=True,
            )

    config = uvicorn.Config(
        app,
        host=settings.host,
        port=settings.port,
        log_level="info",
        access_log=False,
    )
    _ReadyServer(config).run()


if __name__ == "__main__":
    main()
