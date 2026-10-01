"""Documented client flow in a second process, including restart replay."""

import json
import os
import subprocess
import threading
import time
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from open_did_server.identity import sign_headers
from open_did_server.signatures import PROFILE_WHOAMI
from tests.harness import free_port

ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / ".venv" / "bin" / "python"


def _env(data: Path, port: int) -> dict[str, str]:
    env = os.environ.copy()
    for name in (
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
    ):
        env.pop(name, None)
    env.update(
        {
            "OPEN_DID_DATA_DIR": str(data),
            "OPEN_DID_HOST": "127.0.0.1",
            "OPEN_DID_PORT": str(port),
            "PUBLIC_DID_DOMAIN": "example.test",
            "LOCAL_DEMO_MODE": "1",
            "REQUEST_BASE_URL": f"http://127.0.0.1:{port}",
            "PYTHONPATH": str(ROOT / "src"),
        }
    )
    return env


def _run(args, env, check=True) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(PYTHON), *args],
        cwd=ROOT,
        env=env,
        check=check,
        capture_output=True,
        text=True,
    )


class _Server:
    def __init__(self, env) -> None:
        self.env = env
        self.proc: subprocess.Popen | None = None
        self.output: list[str] = []

    def start(self) -> None:
        self.proc = subprocess.Popen(
            [str(PYTHON), "-m", "open_did_server", "serve"],
            cwd=ROOT,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        assert self.proc.stdout is not None
        deadline = time.time() + 20
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                break
            self.output.append(line)
            if "listening on" in line:
                threading.Thread(target=self._drain, daemon=True).start()
                return
        raise RuntimeError("server did not listen:\n" + "".join(self.output))

    def _drain(self) -> None:
        assert self.proc is not None and self.proc.stdout is not None
        for line in self.proc.stdout:
            self.output.append(line)

    def stop(self) -> None:
        if self.proc is None or self.proc.poll() is not None:
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)


def test_client_process_publishes_and_replay_survives_restart(tmp_path):
    port = free_port()
    data = tmp_path / "server-data"
    data.mkdir()
    env = _env(data, port)
    base = f"http://127.0.0.1:{port}"
    init = _run(["-m", "open_did_server", "init"], env)
    assert "initialized" in init.stdout
    grant = _run(
        [
            "-m",
            "open_did_server",
            "create-grant",
            "--owner",
            "demo-owner",
            "--wba-path",
            "identities/wba/alice",
            "--web-path",
            "identities/web/bob",
            "--handle",
            "alice.example.test",
            "--handle",
            "bob.example.test",
        ],
        env,
    )
    token = next(line.split("=", 1)[1].strip() for line in grant.stdout.splitlines() if line.startswith("token="))
    server = _Server(env)
    server.start()
    try:
        client = _run(
            [
                "examples/client/run.py",
                "--base-url",
                base,
                "--token",
                token,
                "--out",
                str(data / "demo"),
            ],
            env,
            check=False,
        )
        print(client.stdout)
        print(client.stderr)
        assert client.returncode == 0, client.stderr
        events = [json.loads(line) for line in client.stdout.splitlines() if line.startswith("{")]
        by_step = {event["step"]: event for event in events}
        assert by_step["wba_document"]["matched"] is True
        assert by_step["web_document"]["matched"] is True
        assert by_step["wba_whoami"]["did"] == by_step["wba_document"]["id"]
        assert by_step["web_whoami"]["did"] == by_step["web_document"]["id"]
        assert by_step["wba_echo"]["body"] == {"hello": "wba"}
        assert by_step["web_echo"]["body"] == {"hello": "web"}
        assert by_step["wba_resolve"]["resolution"] == "development-demo"
        assert by_step["wba_resolve"]["matched"] is True
        assert by_step["web_resolve"]["matched"] is True
        assert by_step["production_https"]["status"] == "not-run"
        assert by_step["wba_forward"]["status"] == "active"
        assert by_step["web_forward"]["did"] == by_step["web_document"]["id"]

        document = json.loads((data / "demo" / "wba-did.json").read_text(encoding="utf-8"))
        private = load_pem_private_key((data / "demo" / "wba-private.pem").read_bytes(), password=None)
        whoami_url = base + "/examples/auth/whoami"
        headers = sign_headers(document, private, "GET", whoami_url, PROFILE_WHOAMI)
        with httpx.Client(trust_env=False, timeout=10) as http:
            first = http.get(whoami_url, headers=headers)
            assert first.status_code == 200, first.text
            assert first.json()["did"] == document["id"]
            replay = http.get(whoami_url, headers=headers)
            assert replay.status_code == 401
            assert replay.json()["error"] == "invalid_nonce"
        server.stop()
        time.sleep(0.3)
        server.start()
        with httpx.Client(trust_env=False, timeout=10) as http:
            after = http.get(whoami_url, headers=headers)
            assert after.status_code == 401, after.text
            assert after.json()["error"] == "invalid_nonce"
            still = http.get(base + by_step["wba_upload"]["content_path"])
            assert still.status_code == 200
            assert still.json()["id"] == document["id"]
    finally:
        server.stop()
