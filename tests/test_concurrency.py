"""Concurrent writers and replays share one SQLite immediate transaction."""

import json
import threading

import httpx

from open_did_server.identity import sign_headers
from open_did_server.signatures import PROFILE_UPDATE, PROFILE_WHOAMI
from tests.harness import started
from tests.test_http_api import _dumps, _grant, _publish, _web


def _send(url, body, headers, results, index):
    with httpx.Client(trust_env=False, timeout=10) as client:
        if body is None:
            response = client.get(url, headers=headers)
        else:
            response = client.put(url, content=body, headers=headers)
        results[index] = (response.status_code, response.text)


def test_one_concurrent_update_commits_and_one_replay_is_accepted():
    with started() as server:
        _grant_id, token = _grant(server, web=["identities/web/bob"])
        web, key = _web()
        published, _raw = _publish(server, web, key, token)
        assert published.status_code == 201, published.text
        document_id = published.json()["document_id"]
        etag = published.json()["etag"]
        url = server.base + f"/api/v1/did-documents/{document_id}"
        prepared = []
        for label in ("one", "two"):
            updated = json.loads(_dumps(web))
            updated["alsoKnownAs"] = [f"https://example.test/{label}"]
            body = _dumps(updated)
            headers = sign_headers(
                web,
                key,
                "PUT",
                url,
                PROFILE_UPDATE,
                body,
                {
                    "Content-Type": "application/json",
                    "If-Match": etag,
                    "ANP-Publication-Token": token,
                },
            )
            prepared.append((body, headers))
        results = [None, None]
        barrier = threading.Barrier(2)

        def worker(index):
            barrier.wait()
            _send(url, prepared[index][0], prepared[index][1], results, index)

        threads = [threading.Thread(target=worker, args=(index,)) for index in (0, 1)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        codes = sorted(item[0] for item in results)
        assert codes == [200, 412], results
        for body, headers in prepared:
            replay = server.client.put(url, content=body, headers=headers)
            assert replay.status_code == 401, replay.text
            assert replay.json()["error"] == "invalid_nonce"

        whoami_url = server.base + "/examples/auth/whoami"
        whoami_headers = sign_headers(web, key, "GET", whoami_url, PROFILE_WHOAMI)
        replay_results = [None, None]

        def replay_worker(index):
            barrier2.wait()
            _send(whoami_url, None, whoami_headers, replay_results, index)

        barrier2 = threading.Barrier(2)
        replay_threads = [threading.Thread(target=replay_worker, args=(index,)) for index in (0, 1)]
        for thread in replay_threads:
            thread.start()
        for thread in replay_threads:
            thread.join()
        assert sorted(item[0] for item in replay_results) == [200, 401], replay_results
        again = server.client.get(whoami_url, headers=whoami_headers)
        assert again.status_code == 401
        assert again.json()["error"] == "invalid_nonce"
