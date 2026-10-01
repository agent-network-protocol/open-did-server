"""HTTP application. Sync endpoints keep SQLite transactions off the event loop."""

from __future__ import annotations

import ipaddress

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from open_did_server import __version__
from open_did_server.config import Settings, load_settings
from open_did_server.errors import ApiError
from open_did_server.service import Result, Service
from open_did_server.signatures import single_header
from open_did_server.store import Store


def _trusted(peer: str, networks: tuple[str, ...]) -> bool:
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return any(address in ipaddress.ip_network(network, strict=False) for network in networks)


def external_target_uri(scope: dict, settings: Settings) -> str:
    """Rebuild the exact URL the client signed.

    Direct clients cannot change that URL with forwarded headers. A peer in
    TRUSTED_PROXY_CIDRS may supply protocol and host after TLS termination.
    """
    raw_path = scope.get("raw_path", scope["path"].encode("utf-8"))
    path = raw_path.decode("latin1") if isinstance(raw_path, bytes) else str(raw_path)
    query = scope.get("query_string", b"")
    if isinstance(query, bytes):
        query = query.decode("latin1")
    if not path.startswith("/"):
        path = "/" + path
    suffix = path if not query else f"{path}?{query}"
    client = scope.get("client")
    peer = client[0] if client else None
    if peer and _trusted(peer, settings.trusted_proxies):
        raw_headers = [
            (name.decode("latin1"), value.decode("latin1"))
            for name, value in scope.get("headers", [])
        ]
        proto = single_header(raw_headers, "x-forwarded-proto")
        host = single_header(raw_headers, "x-forwarded-host")
        if proto not in {"http", "https"} or not host or any(character in host for character in " /\\"):
            raise ApiError(400, "invalid_forwarded_headers", "Trusted proxy forwarded headers are incomplete")
        if not settings.local_demo and proto != "https":
            raise ApiError(400, "invalid_forwarded_headers", "Production forwarded protocol must be https")
        return f"{proto}://{host}{suffix}"
    return f"{settings.request_base_url}{suffix}"


def create_app(settings: Settings | None = None, clock=None) -> FastAPI:
    active = settings or load_settings()
    store = Store(active.database_path)
    service = Service(active, store, clock=clock)
    service.startup()
    app = FastAPI(title="Open DID Server", version=__version__, redirect_slashes=False)
    app.state.settings = active
    app.state.service = service

    @app.middleware("http")
    async def capture_raw(request: Request, call_next):
        body = await request.body()
        if len(body) > active.max_body_bytes:
            return JSONResponse(
                status_code=413,
                content={"error": "payload_too_large", "message": "Request body exceeds 1 MiB"},
            )
        request.state.raw_body = body
        request.state.raw_headers = [
            (name.decode("latin1"), value.decode("latin1"))
            for name, value in request.scope["headers"]
        ]
        try:
            request.state.target_uri = external_target_uri(request.scope, active)
        except ApiError as exc:
            return _api_response(exc)
        return await call_next(request)

    @app.exception_handler(ApiError)
    async def on_api_error(_request: Request, exc: ApiError):
        return _api_response(exc)

    @app.get("/healthz")
    def healthz() -> Response:
        return _from_result(service.health())

    @app.post("/api/v1/did-documents")
    def publish(request: Request) -> Response:
        return _from_result(
            service.publish_document("POST", request.state.target_uri, request.state.raw_headers, request.state.raw_body)
        )

    @app.get("/api/v1/did-documents/{document_id}")
    def metadata(document_id: str) -> Response:
        return _from_result(service.document_metadata(document_id))

    @app.put("/api/v1/did-documents/{document_id}")
    def update(document_id: str, request: Request) -> Response:
        return _from_result(
            service.update_document(
                document_id,
                "PUT",
                request.state.target_uri,
                request.state.raw_headers,
                request.state.raw_body,
            )
        )

    @app.put("/api/v1/handles/{local_part}")
    def put_handle(local_part: str, request: Request) -> Response:
        return _from_result(
            service.put_handle(
                local_part,
                "PUT",
                request.state.target_uri,
                request.state.raw_headers,
                request.state.raw_body,
            )
        )

    @app.get("/.well-known/handle/{local_part}")
    def read_handle(local_part: str) -> Response:
        return _from_result(service.read_handle(local_part))

    @app.get("/api/v1/handles/by-did")
    def read_by_did(did: str = "") -> Response:
        return _from_result(service.read_handle_by_did(did))

    @app.get("/examples/auth/whoami")
    def whoami(request: Request) -> Response:
        return _from_result(
            service.whoami("GET", request.state.target_uri, request.state.raw_headers, request.state.raw_body)
        )

    @app.post("/examples/auth/echo")
    def echo(request: Request) -> Response:
        return _from_result(
            service.echo("POST", request.state.target_uri, request.state.raw_headers, request.state.raw_body)
        )

    @app.api_route("/.well-known/did.json", methods=["GET", "HEAD"])
    def read_root(request: Request) -> Response:
        return _read_did(request, "/.well-known/did.json")

    @app.api_route("/{full_path:path}", methods=["GET", "HEAD"])
    def read_path(request: Request, full_path: str) -> Response:
        del full_path
        raw_path = request.scope.get("raw_path", request.url.path.encode("utf-8"))
        path = raw_path.decode("latin1") if isinstance(raw_path, bytes) else request.url.path
        return _read_did(request, path)

    def _read_did(request: Request, path: str) -> Response:
        if_none_match = None
        try:
            if_none_match = single_header(request.state.raw_headers, "if-none-match")
        except ApiError as exc:
            return _api_response(exc)
        accept = None
        try:
            accept = single_header(request.state.raw_headers, "accept")
        except ApiError as exc:
            return _api_response(exc)
        return _from_result(service.read_distributed(path, request.method, if_none_match, accept))

    return app


def _api_response(exc: ApiError) -> JSONResponse:
    headers: dict[str, str] = {}
    if exc.status == 401:
        headers["Cache-Control"] = "no-store"
    if exc.www_authenticate:
        headers["WWW-Authenticate"] = exc.www_authenticate
    if exc.accept_signature:
        headers["Accept-Signature"] = exc.accept_signature
    return JSONResponse(
        status_code=exc.status,
        content={"error": exc.error, "message": exc.message},
        headers=headers,
    )


def _from_result(result: Result) -> Response:
    if result.media_type == "application/did+json":
        content = b"" if result.body is None else result.body
        return Response(content=content, status_code=result.status, media_type=result.media_type, headers=result.headers)
    if result.body is None:
        return Response(status_code=result.status, headers=result.headers)
    return JSONResponse(status_code=result.status, content=result.body, headers=result.headers)
