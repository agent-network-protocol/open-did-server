"""Process configuration. Secrets are not given defaults."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    data_dir: str
    host: str
    port: int
    public_did_domain: str
    public_did_port: int
    handle_provider_domain: str
    request_base_url: str
    local_demo: bool
    resolution_override: str | None
    trusted_proxies: tuple[str, ...]
    root_method: str | None
    cache_seconds: int = 60
    signature_lifetime: int = 300
    clock_skew: int = 30
    max_body_bytes: int = 1024 * 1024

    @property
    def wba_handles_enabled(self) -> bool:
        return self.public_did_domain == self.handle_provider_domain

    @property
    def database_path(self) -> str:
        return os.path.join(self.data_dir, "server.db")

    @property
    def high_water_path(self) -> str:
        return os.path.join(self.data_dir, "high-water.json")

    def origin(self) -> str:
        if self.public_did_port == 443:
            return f"https://{self.public_did_domain}"
        return f"https://{self.public_did_domain}:{self.public_did_port}"


def _flag(name: str, default: str) -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _domain(value: str, label: str) -> str:
    host = value.strip().lower().rstrip(".")
    if not host or ":" in host or "/" in host or "@" in host:
        raise SystemExit(f"{label} must be a DNS hostname without a port")
    labels = host.split(".")
    if len(labels) < 2 or not any(character.isalpha() for character in labels[-1]):
        raise SystemExit(f"{label} must be a DNS hostname")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    raise SystemExit(f"{label} must not be an IP address")


def load_settings() -> Settings:
    """Load settings from the environment."""
    data_dir = os.environ.get("OPEN_DID_DATA_DIR", "./data")
    public_domain = _domain(os.environ.get("PUBLIC_DID_DOMAIN", "example.test"), "PUBLIC_DID_DOMAIN")
    provider = _domain(
        os.environ.get("HANDLE_PROVIDER_DOMAIN", public_domain),
        "HANDLE_PROVIDER_DOMAIN",
    )
    public_port = int(os.environ.get("PUBLIC_DID_PORT", "443"))
    if not 1 <= public_port <= 65535:
        raise SystemExit("PUBLIC_DID_PORT is out of range")
    host = os.environ.get("OPEN_DID_HOST", "127.0.0.1")
    port = int(os.environ.get("OPEN_DID_PORT", "8000"))
    local_demo = _flag("LOCAL_DEMO_MODE", "1")
    base = os.environ.get("REQUEST_BASE_URL", f"http://{host}:{port}").rstrip("/")
    override = os.environ.get("DID_RESOLUTION_BASE_URL_OVERRIDE", "").strip() or None
    if override and not local_demo:
        raise SystemExit("DID_RESOLUTION_BASE_URL_OVERRIDE is only valid in LOCAL_DEMO_MODE")
    if local_demo and not base.startswith(("http://", "https://")):
        raise SystemExit("REQUEST_BASE_URL must be an absolute HTTP URL")
    if not local_demo and not base.startswith("https://"):
        raise SystemExit("production REQUEST_BASE_URL must use HTTPS")
    root = os.environ.get("ROOT_DID_METHOD", "").strip().lower() or None
    if root not in {None, "wba", "web"}:
        raise SystemExit("ROOT_DID_METHOD must be wba, web, or empty")
    proxies = tuple(
        item.strip()
        for item in os.environ.get("TRUSTED_PROXY_CIDRS", "").split(",")
        if item.strip()
    )
    for item in proxies:
        ipaddress.ip_network(item, strict=False)
    return Settings(
        data_dir=data_dir,
        host=host,
        port=port,
        public_did_domain=public_domain,
        public_did_port=public_port,
        handle_provider_domain=provider,
        request_base_url=base,
        local_demo=local_demo,
        resolution_override=override,
        trusted_proxies=proxies,
        root_method=root,
    )
