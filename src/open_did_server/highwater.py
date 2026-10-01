"""Sidecar high-water file for facts a database snapshot can roll back."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass

from anp.wns.binding import canonicalize_binding_generation


@dataclass(frozen=True)
class Facts:
    generations: dict[str, str]
    tombstones: tuple[str, ...]
    revoked_grants: tuple[str, ...]
    stable_paths: dict[str, str]

    def to_json(self) -> dict:
        return {
            "version": 1,
            "generations": dict(sorted(self.generations.items())),
            "tombstones": list(self.tombstones),
            "revoked_grants": list(self.revoked_grants),
            "stable_paths": dict(sorted(self.stable_paths.items())),
        }


EMPTY = Facts({}, (), (), {})


def _canonical_generation(value: str) -> int:
    return int(canonicalize_binding_generation(value))


def satisfies(reference: Facts, current: Facts) -> bool:
    """Return whether every sidecar fact is still present in the database."""
    try:
        for handle, generation in reference.generations.items():
            actual = current.generations.get(handle)
            if actual is None or _canonical_generation(actual) < _canonical_generation(generation):
                return False
        for handle in reference.tombstones:
            if handle not in current.tombstones:
                return False
        for grant_id in reference.revoked_grants:
            if grant_id not in current.revoked_grants:
                return False
    except ValueError:
        return False
    for key, owner in reference.stable_paths.items():
        if current.stable_paths.get(key) != owner:
            return False
    return True


def read_facts(path: str) -> Facts | None:
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise ValueError("high-water file is not version 1")
    generations = payload.get("generations") or {}
    stable = payload.get("stable_paths") or {}
    if not isinstance(generations, dict) or not isinstance(stable, dict):
        raise ValueError("high-water file is malformed")
    return Facts(
        generations={str(key): str(value) for key, value in generations.items()},
        tombstones=tuple(str(item) for item in payload.get("tombstones") or []),
        revoked_grants=tuple(str(item) for item in payload.get("revoked_grants") or []),
        stable_paths={str(key): str(value) for key, value in stable.items()},
    )


def write_facts(path: str, facts: Facts) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    data = (json.dumps(facts.to_json(), indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd, temporary = tempfile.mkstemp(dir=directory, prefix=".high-water-")
    try:
        os.write(fd, data)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, path)
        temporary = ""
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)
