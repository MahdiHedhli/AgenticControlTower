from __future__ import annotations

import json
import sqlite3
from typing import Any

from ..ids import new_id
from ..security import expires_in, hash_token, now_utc, parse_utc, utc_iso


class IdentityStoreMixin:
    def create_pairing_session(
        self,
        *,
        node_id: str,
        node_fingerprint: str,
        display_name: str,
        requested_permissions: list[str],
        clearance_channel: str,
        pairing_token: str,
        challenge: str,
        ttl_seconds: int,
    ) -> dict[str, Any]:
        pairing_id = new_id("pair")
        expires_at = utc_iso(expires_in(ttl_seconds))
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO pairing_sessions (
                    pairing_id, pairing_token_hash, challenge, status, node_id,
                    node_fingerprint, display_name, requested_permissions_json,
                    clearance_channel, expires_at, created_at
                )
                VALUES (?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    pairing_id,
                    hash_token(pairing_token),
                    challenge,
                    node_id,
                    node_fingerprint,
                    display_name,
                    json.dumps(requested_permissions),
                    clearance_channel,
                    expires_at,
                    utc_iso(),
                ),
            )
        return self.get_pairing_session(pairing_id, include_token=False) | {
            "pairing_token": pairing_token
        }

    def get_pairing_session(
        self, pairing_id: str, *, include_token: bool = False
    ) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM pairing_sessions WHERE pairing_id = ?", (pairing_id,)
            ).fetchone()
        if row is None:
            raise KeyError(pairing_id)
        pairing = dict(row)
        pairing["requested_permissions"] = json.loads(pairing.pop("requested_permissions_json"))
        if not include_token:
            pairing.pop("pairing_token_hash", None)
        return pairing

    def set_pairing_status(self, pairing_id: str, status: str) -> None:
        completed_at = utc_iso() if status == "completed" else None
        with self.connect() as db:
            db.execute(
                "UPDATE pairing_sessions SET status = ?, completed_at = ? WHERE pairing_id = ?",
                (status, completed_at, pairing_id),
            )

    def create_device(
        self,
        *,
        node_id: str,
        device_name: str,
        platform: str,
        app_instance_id: str,
        app_version: str | None,
        device_public_key: str,
        permissions: list[str],
        clearance_channel: str = "local_terminal",
        device_key_algorithm: str = "ed25519",
        push_token: str | None = None,
    ) -> dict[str, Any]:
        device_id = new_id("dev")
        registered_at = utc_iso()
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO devices (
                    device_id, user_id, node_id, device_name, platform, app_instance_id,
                    app_version, device_public_key, device_key_algorithm, clearance_channel,
                    push_token, status, permissions_json, registered_at, last_seen_at
                )
                VALUES (?, 'owner', ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
                """,
                (
                    device_id,
                    node_id,
                    device_name,
                    platform,
                    app_instance_id,
                    app_version,
                    device_public_key,
                    device_key_algorithm,
                    clearance_channel,
                    push_token,
                    json.dumps(permissions),
                    registered_at,
                    registered_at,
                ),
            )
        return self.get_device(device_id)

    def set_device_push_token(self, device_id: str, push_token: str | None) -> dict[str, Any]:
        """Update an already-paired device's APNs push token (registered by the
        app after it obtains a token from APNs)."""
        with self.connect() as db:
            db.execute(
                "UPDATE devices SET push_token = ? WHERE device_id = ?",
                (push_token or None, device_id),
            )
        return self.get_device(device_id)

    def push_targets(self, node_id: str) -> list[str]:
        """Active mobile_signed devices on a node that have a push token."""
        with self.connect() as db:
            rows = db.execute(
                """
                SELECT push_token FROM devices
                WHERE node_id = ? AND status = 'active'
                  AND clearance_channel = 'mobile_signed'
                  AND push_token IS NOT NULL AND push_token != ''
                """,
                (node_id,),
            ).fetchall()
        return [row["push_token"] for row in rows]

    def get_device(self, device_id: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
        if row is None:
            raise KeyError(device_id)
        device = dict(row)
        device["permissions"] = json.loads(device.pop("permissions_json"))
        return device

    def list_devices(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM devices ORDER BY registered_at DESC").fetchall()
        devices = []
        for row in rows:
            device = dict(row)
            device["permissions"] = json.loads(device.pop("permissions_json"))
            devices.append(device)
        return devices

    def revoke_device(self, device_id: str) -> bool:
        with self.connect() as db:
            cursor = db.execute(
                "UPDATE devices SET status = 'revoked' WHERE device_id = ?", (device_id,)
            )
            db.execute(
                "UPDATE auth_tokens SET revoked_at = ? WHERE device_id = ?",
                (utc_iso(), device_id),
            )
        return cursor.rowcount > 0

    def create_auth_token(
        self, *, token: str, token_type: str, device_id: str, ttl_seconds: int
    ) -> None:
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO auth_tokens (token_hash, token_type, device_id, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    hash_token(token),
                    token_type,
                    device_id,
                    utc_iso(expires_in(ttl_seconds)),
                    utc_iso(),
                ),
            )

    def verify_access_token(self, token: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """
                SELECT d.*
                FROM auth_tokens t
                JOIN devices d ON d.device_id = t.device_id
                WHERE t.token_hash = ?
                  AND t.token_type = 'access'
                  AND t.revoked_at IS NULL
                  AND d.status = 'active'
                """,
                (hash_token(token),),
            ).fetchone()
        if row is None:
            return None
        token_row = self._get_token(token)
        if token_row is None or parse_utc(token_row["expires_at"]) <= now_utc():
            return None
        device = dict(row)
        device["permissions"] = json.loads(device.pop("permissions_json"))
        return device

    def verify_refresh_token(self, token: str) -> dict[str, Any] | None:
        token_row = self._get_token(token)
        if token_row is None or token_row["token_type"] != "refresh":
            return None
        if token_row["revoked_at"] or parse_utc(token_row["expires_at"]) <= now_utc():
            return None
        device = self.get_device(token_row["device_id"])
        if device["status"] != "active":
            return None
        return device

    def _get_token(self, token: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM auth_tokens WHERE token_hash = ?", (hash_token(token),)
            ).fetchone()
        return dict(row) if row else None

    def record_request_nonce(self, *, device_id: str, nonce: str, timestamp: int) -> bool:
        try:
            with self.connect() as db:
                db.execute(
                    """
                    INSERT INTO request_nonces (device_id, nonce, timestamp, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (device_id, nonce, timestamp, utc_iso()),
                )
        except sqlite3.IntegrityError:
            return False
        return True
