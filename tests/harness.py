"""Real loopback server fixture. Requests do not inherit ambient proxies."""

from __future__ import annotations

import socket
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

import httpx
import uvicorn

from open_did_server.app import create_app
from open_did_server.config import Settings
from open_did_server.service import Service
from open_did_server.store import Store


@dataclass
class Running:
    base: str
    settings: Settings
    client: httpx.Client
    service: Service
    tmp: Path


class _Server:
    def __init__(self, settings: Settings, clock=None) -> None:
        self.app = create_app(settings, clock=clock)
        self.config = uvicorn.Config(
            self.app,
            host="127.0.0.1",
            port=settings.port,
            log_level="warning",
            access_log=False,
        )
        self.server = uvicorn.Server(self.config)
        self.server.install_signal_handlers = lambda: None
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def start(self) -> None:
        self.thread.start()
        for _ in range(200):
            if self.server.started:
                return
            import time
            time.sleep(0.02)
        raise RuntimeError("server did not start")

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=5)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def make_settings(tmp: Path, port: int, **overrides) -> Settings:
    values = dict(
        data_dir=str(tmp),
        host="127.0.0.1",
        port=port,
        public_did_domain="example.test",
        public_did_port=443,
        handle_provider_domain="example.test",
        request_base_url=f"http://127.0.0.1:{port}",
        local_demo=True,
        resolution_override=None,
        trusted_proxies=(),
        root_method=None,
    )
    values.update(overrides)
    if "request_base_url" not in overrides:
        values["request_base_url"] = f"http://127.0.0.1:{port}"
    return Settings(**values)


class started:
    def __init__(self, clock=None, **overrides) -> None:
        self.clock = clock
        self.overrides = overrides
        self.server: _Server | None = None
        self.client: httpx.Client | None = None
        self.tmp = Path(tempfile.mkdtemp())

    def __enter__(self) -> Running:
        port = free_port()
        settings = make_settings(self.tmp, port, **self.overrides)
        service = Service(settings, Store(settings.database_path), clock=self.clock)
        service.startup()
        self.server = _Server(settings, clock=self.clock)
        self.server.start()
        self.client = httpx.Client(trust_env=False, timeout=10)
        return Running(f"http://127.0.0.1:{port}", settings, self.client, service, self.tmp)

    def __exit__(self, *exc) -> None:
        if self.client is not None:
            self.client.close()
        if self.server is not None:
            self.server.stop()
