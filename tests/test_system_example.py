"""The documented system-test example runs in a separate process over real HTTP."""

import json
import os
import subprocess
import threading
import time
from pathlib import Path

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
            "PUBLIC_DID_PORT": "443",
            "HANDLE_PROVIDER_DOMAIN": "example.test",
            "LOCAL_DEMO_MODE": "1",
            "REQUEST_BASE_URL": f"http://127.0.0.1:{port}",
            "PYTHONPATH": str(ROOT / "src"),
        }
    )
    return env


def _run(args, env) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(PYTHON), *args],
        cwd=ROOT,
        env=env,
        check=True,
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


def test_system_example_reports_wba_web_and_replay(tmp_path):
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    data = tmp_path / "server-data"
    data.mkdir()
    env = _env(data, port)
    base = f"http://127.0.0.1:{port}"
    _run(["-m", "open_did_server", "init"], env)
    grant = _run(
        [
            "-m",
            "open_did_server",
            "create-grant",
            "--owner",
            "system-example",
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
        client = subprocess.run(
            [
                str(PYTHON),
                "examples/system/run.py",
                "--base-url",
                base,
                "--token",
                token,
                "--domain",
                "example.test",
                "--out",
                str(data / "demo"),
            ],
            cwd=ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        print(client.stdout)
        print(client.stderr)
        assert client.returncode == 0, client.stderr
        events = [json.loads(line) for line in client.stdout.splitlines() if line.startswith("{")]
        by_case = {event["case"]: event for event in events}
        for name in (
            "wba-publish",
            "wba-read",
            "wba-handle",
            "wba-whoami",
            "wba-echo",
            "web-publish",
            "web-read",
            "web-handle",
            "web-whoami",
            "web-echo",
        ):
            assert by_case[name]["result"] == "pass", by_case[name]
            assert by_case[name]["http"] < 400
        assert by_case["wba-create"]["result"] == "pass"
        assert by_case["wba-create"]["published"] is False
        assert by_case["web-create"]["published"] is False
        assert by_case["wba-create"]["id"] == by_case["wba-publish"]["id"]
        assert by_case["web-create"]["id"] == by_case["web-publish"]["id"]
        assert by_case["wba-publish"]["published"] is True
        assert by_case["web-publish"]["published"] is True
        assert by_case["wba-read"]["matched"] is True
        assert by_case["web-read"]["matched"] is True
        assert by_case["wba-read"]["id"].startswith("did:wba:")
        assert by_case["web-read"]["id"].startswith("did:web:")
        assert by_case["wba-whoami"]["did"] == by_case["wba-read"]["id"]
        assert by_case["web-whoami"]["did"] == by_case["web-read"]["id"]
        assert by_case["wba-whoami"]["authenticated"] is True
        assert by_case["web-whoami"]["authenticated"] is True
        assert by_case["wba-whoami"]["auth_scheme"] == "http_signatures"
        assert by_case["wba-echo"]["body"] == {"hello": "wba"}
        assert by_case["web-echo"]["did"] == by_case["web-read"]["id"]
        assert by_case["web-echo"]["auth_scheme"] == "http_signatures"
        assert by_case["wba-handle"]["did"] == by_case["wba-read"]["id"]
        assert by_case["web-handle"]["status"] == "active"
        replay = by_case["whoami-replay"]
        assert replay["result"] == "rejected"
        assert replay["http"] == 401
        assert replay["error"] == "invalid_nonce"
        assert "token" not in client.stdout
        assert "BEGIN " not in client.stdout
    finally:
        server.stop()
