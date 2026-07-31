from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature
from fastapi import FastAPI, HTTPException, Request, status

from ..config import Settings
from ..schemas import (
    AuthTokenSet,
    CompletePairingRequest,
    CompletePairingResponse,
    CreatePairingSessionRequest,
    Device,
    Node,
    PairingSession,
    RefreshTokenRequest,
)
from ..security import compare_token, expires_in, new_token, now_utc
from ..signing import (
    DEFAULT_KEY_ALGORITHM,
    SUPPORTED_KEY_ALGORITHMS,
    VerifiedDevice,
    verify_payload_signature,
)
from ..store import SQLiteStore


def register_identity_routes(
    *,
    app: FastAPI,
    store: SQLiteStore,
    settings: Settings,
    signed_device_dependency: Any,
    default_permissions: list[str],
    request_id: Callable[[Request], str],
    expire_pairing_if_needed: Callable[[SQLiteStore, dict[str, Any]], dict[str, Any]],
) -> None:
    @app.post(
        "/v1/pairing/start",
        response_model=PairingSession,
        status_code=status.HTTP_201_CREATED,
    )
    @app.post(
        "/v1/pairing/sessions", response_model=PairingSession, status_code=status.HTTP_201_CREATED
    )
    def start_pairing(payload: CreatePairingSessionRequest, request: Request) -> PairingSession:
        ttl_seconds = (
            payload.ttl_seconds
            if payload.ttl_seconds is not None
            else settings.pairing_ttl_seconds
        )
        pairing_token = new_token()
        pairing = store.create_pairing_session(
            node_id=settings.node_id,
            node_fingerprint=settings.node_fingerprint,
            display_name=payload.display_name,
            requested_permissions=payload.requested_permissions,
            clearance_channel=payload.clearance_channel,
            pairing_token=pairing_token,
            challenge=new_token(),
            ttl_seconds=ttl_seconds,
        )
        store.append_audit_event(
            event_type="pairing_started",
            actor_type="gateway",
            actor_id="gateway",
            node_id=settings.node_id,
            request_id=request_id(request),
            payload_redacted={
                "pairing_id": pairing["pairing_id"],
                "clearance_channel": pairing["clearance_channel"],
            },
        )
        return PairingSession.model_validate(pairing)

    @app.get("/v1/pairing/sessions/{pairing_id}", response_model=PairingSession)
    def get_pairing(pairing_id: str) -> PairingSession:
        try:
            pairing = store.get_pairing_session(pairing_id)
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "pairing session not found") from exc
        return PairingSession.model_validate(expire_pairing_if_needed(store, pairing))

    @app.post("/v1/pairing/complete", response_model=CompletePairingResponse)
    def complete_pairing(
        payload: CompletePairingRequest, request: Request
    ) -> CompletePairingResponse:
        try:
            pairing = store.get_pairing_session(payload.pairing_id, include_token=True)
        except KeyError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid pairing token") from exc

        pairing = expire_pairing_if_needed(store, pairing)
        if pairing["status"] != "pending":
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"pairing session is {pairing['status']}",
            )
        if not compare_token(payload.challenge_response, pairing["pairing_token_hash"]):
            store.append_audit_event(
                event_type="pairing_rejected",
                actor_type="gateway",
                actor_id="gateway",
                node_id=pairing["node_id"],
                request_id=request_id(request),
                payload_redacted={"pairing_id": pairing["pairing_id"], "reason": "invalid_token"},
            )
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid pairing token")

        permissions = pairing["requested_permissions"] or default_permissions
        if (
            payload.device.clearance_channel is not None
            and payload.device.clearance_channel != pairing["clearance_channel"]
        ):
            store.append_audit_event(
                event_type="pairing_rejected",
                actor_type="gateway",
                actor_id="gateway",
                node_id=pairing["node_id"],
                request_id=request_id(request),
                payload_redacted={
                    "pairing_id": pairing["pairing_id"],
                    "reason": "device_clearance_channel_conflict",
                    "session_clearance_channel": pairing["clearance_channel"],
                    "device_clearance_channel": payload.device.clearance_channel,
                },
            )
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "device clearance channel mismatch")

        device_key_algorithm = (payload.device_key_algorithm or DEFAULT_KEY_ALGORITHM).lower()
        if device_key_algorithm not in SUPPORTED_KEY_ALGORITHMS:
            store.append_audit_event(
                event_type="pairing_rejected",
                actor_type="gateway",
                actor_id="gateway",
                node_id=pairing["node_id"],
                request_id=request_id(request),
                payload_redacted={
                    "pairing_id": pairing["pairing_id"],
                    "reason": "unsupported_key_algorithm",
                    "device_key_algorithm": device_key_algorithm,
                },
            )
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "unsupported device key algorithm")

        # A hardware-backed (p256) enrolment MUST prove control of the private key by signing the
        # session challenge. Legacy ed25519 enrolments may supply the proof but are not required to,
        # preserving backward compatibility. The proof is verified against the same canonical bytes
        # (the challenge) both sides agree on.
        possession_proof = payload.device_key_possession_proof
        if device_key_algorithm == "p256" and not possession_proof:
            store.append_audit_event(
                event_type="pairing_rejected",
                actor_type="gateway",
                actor_id="gateway",
                node_id=pairing["node_id"],
                request_id=request_id(request),
                payload_redacted={
                    "pairing_id": pairing["pairing_id"],
                    "reason": "device_key_possession_proof_required",
                },
            )
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "device key possession proof required"
            )
        if possession_proof is not None:
            try:
                verify_payload_signature(
                    algorithm=device_key_algorithm,
                    public_key_b64=payload.device_public_key,
                    signature_b64=possession_proof,
                    message=pairing["challenge"].encode("utf-8"),
                )
            except (ValueError, InvalidSignature) as exc:
                store.append_audit_event(
                    event_type="pairing_rejected",
                    actor_type="gateway",
                    actor_id="gateway",
                    node_id=pairing["node_id"],
                    request_id=request_id(request),
                    payload_redacted={
                        "pairing_id": pairing["pairing_id"],
                        "reason": "device_key_possession_proof_invalid",
                    },
                )
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST, "invalid device key possession proof"
                ) from exc

        device = store.create_device(
            node_id=pairing["node_id"],
            device_name=payload.device.device_name,
            platform=payload.device.platform,
            app_instance_id=payload.device.app_instance_id,
            app_version=payload.device.app_version,
            device_public_key=payload.device_public_key,
            permissions=permissions,
            clearance_channel=pairing["clearance_channel"],
            device_key_algorithm=device_key_algorithm,
            push_token=payload.device.push_token,
        )
        access_token = new_token()
        refresh_token = new_token()
        store.create_auth_token(
            token=access_token,
            token_type="access",
            device_id=device["device_id"],
            ttl_seconds=15 * 60,
        )
        store.create_auth_token(
            token=refresh_token,
            token_type="refresh",
            device_id=device["device_id"],
            ttl_seconds=30 * 24 * 60 * 60,
        )
        store.set_pairing_status(pairing["pairing_id"], "completed")
        store.append_audit_event(
            event_type="device_registered",
            actor_type="device",
            actor_id=device["device_id"],
            node_id=pairing["node_id"],
            request_id=request_id(request),
            payload_redacted={
                "pairing_id": pairing["pairing_id"],
                "platform": payload.device.platform,
                "permissions": permissions,
            },
        )
        store.create_event(
            node_id=pairing["node_id"],
            event_type="system.health",
            payload={"status": "healthy", "reason": "device_registered"},
        )
        return CompletePairingResponse(
            node=Node.model_validate(store.get_node(pairing["node_id"])),
            device=Device.model_validate(device),
            tokens=AuthTokenSet(
                access_token=access_token,
                refresh_token=refresh_token,
                expires_at=now_utc() + timedelta(minutes=15),
            ),
        )

    @app.post("/v1/auth/token/refresh", response_model=AuthTokenSet)
    def refresh_token(
        payload: RefreshTokenRequest,
        signed_device: VerifiedDevice = signed_device_dependency,
    ) -> AuthTokenSet:
        device = store.verify_refresh_token(payload.refresh_token)
        if device is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid refresh token")
        if device["device_id"] != signed_device.device_id:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "refresh token device mismatch")
        access_token = new_token()
        refresh_token_value = new_token()
        store.create_auth_token(
            token=access_token,
            token_type="access",
            device_id=device["device_id"],
            ttl_seconds=15 * 60,
        )
        store.create_auth_token(
            token=refresh_token_value,
            token_type="refresh",
            device_id=device["device_id"],
            ttl_seconds=30 * 24 * 60 * 60,
        )
        return AuthTokenSet(
            access_token=access_token,
            refresh_token=refresh_token_value,
            expires_at=expires_in(15 * 60),
        )

    @app.get("/v1/devices")
    def list_devices(
        _device: VerifiedDevice = signed_device_dependency,
    ) -> dict[str, list[Device]]:
        return {"devices": [Device.model_validate(device) for device in store.list_devices()]}

    @app.delete("/v1/devices/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
    def revoke_device(
        device_id: str,
        request: Request,
        device: VerifiedDevice = signed_device_dependency,
    ) -> None:
        if not store.revoke_device(device_id):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
        store.append_audit_event(
            event_type="device_revoked",
            actor_type="device",
            actor_id=device.device_id,
            node_id=settings.node_id,
            request_id=request_id(request),
            payload_redacted={"device_id": device_id},
        )
        # Cascade: a revoked device's standing grants must not outlive it.
        # The read-side liveness gate in ``grants.py`` is the load-bearing
        # control (it also covers rows this loop never sees — a hand-flipped
        # status, a crash between the UPDATE above and here); this write keeps
        # ``GET /v1/approval-grants`` honest and audits the withdrawal per
        # grant, exactly like ``POST /v1/approval-grants/<id>/revoke`` does.
        revoked_by = f"device_revoked:{device_id}"
        for grant in store.list_approval_grants(state="active"):
            if grant.get("granted_by_device_id") != device_id:
                continue
            revoked = store.revoke_approval_grant(grant["grant_id"], revoked_by=revoked_by)
            store.append_audit_event(
                event_type="capability_grant_revoked",
                actor_type="device",
                actor_id=device.device_id,
                node_id=revoked["node_id"],
                agent_id=revoked["agent_id"],
                session_id=revoked.get("session_id"),
                approval_id=revoked["source_approval_id"],
                request_id=request_id(request),
                payload_redacted={
                    "grant_id": revoked["grant_id"],
                    "scope": revoked["scope"],
                    "requested_tool": revoked["requested_tool"],
                    "risk_family": revoked["risk_family"],
                    "source_approval_id": revoked["source_approval_id"],
                    "revoked_at": revoked["revoked_at"],
                    "revoked_by": revoked_by,
                },
            )
            store.create_event(
                node_id=revoked["node_id"],
                agent_id=revoked["agent_id"],
                session_id=revoked.get("session_id"),
                event_type="capability_grant.revoked",
                payload={
                    "grant_id": revoked["grant_id"],
                    "scope": revoked["scope"],
                    "requested_tool": revoked["requested_tool"],
                    "revoked_by": revoked_by,
                },
            )
