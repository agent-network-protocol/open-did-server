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
    nonce_watermark: int = 0
    replay_resume_after: int = 0

    def to_json(self) -> dict:
        return {
            "version": 1,
            "generations": dict(sorted(self.generations.items())),
            "tombstones": list(self.tombstones),
            "revoked_grants": list(self.revoked_grants),
            "stable_paths": dict(sorted(self.stable_paths.items())),
            "nonce_watermark": self.nonce_watermark,
            "replay_resume_after": self.replay_resume_after,
        }


EMPTY = Facts({}, (), (), {})


def _canonical_generation(value: str) -> int:
    return int(canonicalize_binding_generation(value))


def structural_satisfies(reference: Facts, current: Facts) -> bool:
    """Return whether generations, tombstones, revoked grants, and stable paths remain."""
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


def replay_watermark_satisfied(reference: Facts, current: Facts) -> bool:
    """Return whether the database still contains every consumed replay nonce generation."""
    return current.nonce_watermark >= reference.nonce_watermark


def satisfies(reference: Facts, current: Facts) -> bool:
    """Return whether every sidecar fact is still present in the database."""
    return structural_satisfies(reference, current) and replay_watermark_satisfied(reference, current)


@dataclass(frozen=True)
class Recovery:
    structural_ok: bool
    replay_behind: bool
    resume_after: int
    clearable: bool
    watermark: int


def decide_recovery(
    reference: Facts | None,
    current: Facts,
    now: int,
    ordinary_span: int,
    replay_span: int,
    sidecar_replay_resume_after: int = 0,
) -> Recovery:
    """Decide restore maintenance without reading SQLite.

    A structural miss is never clearable by waiting. A nonce gap publishes
    ``resume_after = max(sidecar deadline, now + replay_span)`` from this call's
    clock. Startup persists that value. Clearing the gap is allowed only when
    structural facts match and the previously stored deadline is already due.
    The watermark to persist is the higher counter, never the restored database.
    ``ordinary_span`` is the operator maintenance window and is not a replay clock.
    """
    if ordinary_span < 0 or replay_span < 0:
        raise ValueError("maintenance span must be non-negative")
    if reference is None:
        return Recovery(True, False, 0, True, current.nonce_watermark)
    structural_ok = structural_satisfies(reference, current)
    replay_behind = current.nonce_watermark < reference.nonce_watermark
    watermark = max(current.nonce_watermark, reference.nonce_watermark)
    stored = sidecar_replay_resume_after if sidecar_replay_resume_after > 0 else 0
    if replay_behind:
        resume_after = max(stored, now + replay_span)
        clearable = structural_ok and stored > 0 and now >= stored
    else:
        resume_after = 0
        clearable = structural_ok
    return Recovery(structural_ok, replay_behind, resume_after, clearable, watermark)


def read_facts(path: str) -> Facts | None:
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise ValueError("high-water file is not version 1")
    generations = payload.get("generations") or {}
    stable = payload.get("stable_paths") or {}
    watermark = payload.get("nonce_watermark", 0)
    resume_after = payload.get("replay_resume_after", 0)
    if not isinstance(generations, dict) or not isinstance(stable, dict):
        raise ValueError("high-water file is malformed")
    if isinstance(watermark, bool) or not isinstance(watermark, int) or watermark < 0:
        raise ValueError("high-water file is malformed")
    if isinstance(resume_after, bool) or not isinstance(resume_after, int) or resume_after < 0:
        raise ValueError("high-water file is malformed")
    return Facts(
        generations={str(key): str(value) for key, value in generations.items()},
        tombstones=tuple(str(item) for item in payload.get("tombstones") or []),
        revoked_grants=tuple(str(item) for item in payload.get("revoked_grants") or []),
        stable_paths={str(key): str(value) for key, value in stable.items()},
        nonce_watermark=watermark,
        replay_resume_after=resume_after,
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
