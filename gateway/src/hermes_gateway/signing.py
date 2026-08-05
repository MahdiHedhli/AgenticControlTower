from __future__ import annotations

import base64
import hashlib
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import HTTPException, Request, status

from .config import Settings
from .ids import new_id
from .security import content_hash
from .store import SQLiteStore

SIGNING_VERSION = "HMCP-SIGN-V1"
TIMESTAMP_TOLERANCE_SECONDS = 300

# Device signing-key algorithms accepted for the mobile_signed channel.
# ed25519: legacy/software keys (raw 32-byte public key, EdDSA, raw 64-byte signature).
# p256:    Apple Secure Enclave / Android Keystore keys. The Secure Enclave only supports
#          ECDSA P-256 (secp256r1), so a genuine hardware-backed key must use this algorithm.
#          Public key = X9.63 uncompressed point (0x04 || X || Y, 65 bytes); signature = DER
#          ECDSA over SHA-256. Adding this is purely additive: the canonical signing string
#          (canonical_request) is unchanged, the per-device algorithm is recorded at enrolment,
#          and the ed25519 path is preserved.
DEFAULT_KEY_ALGORITHM = "ed25519"
SUPPORTED_KEY_ALGORITHMS = ("ed25519", "p256")

DEVICE_ID_HEADER = "X-HMCP-Device-Id"
TIMESTAMP_HEADER = "X-HMCP-Timestamp"
NONCE_HEADER = "X-HMCP-Nonce"
SIGNATURE_HEADER = "X-HMCP-Signature"
KEY_ID_HEADER = "X-HMCP-Key-Id"


@dataclass(frozen=True)
class VerifiedDevice:
    device_id: str
    node_id: str
    permissions: list[str]
    clearance_channel: str = "local_terminal"


def canonical_request(
    *,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> str:
    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join(
        [
            SIGNING_VERSION,
            method.upper(),
            path,
            timestamp,
            nonce,
            body_hash,
        ]
    )


def verify_payload_signature(
    *,
    algorithm: str | None,
    public_key_b64: str,
    signature_b64: str,
    message: bytes,
) -> None:
    """Verify a device signature over ``message`` for the device's enrolled key algorithm.

    Raises ``ValueError`` (malformed key/algorithm) or
    ``cryptography.exceptions.InvalidSignature`` (bad signature) on failure; returns ``None``
    on success. All encoded values are base64url (padding optional). The message bytes are the
    exact UTF-8 canonical string both sides agree on — this helper never changes that string.
    """
    algorithm = (algorithm or DEFAULT_KEY_ALGORITHM).lower()
    signature = _b64decode(signature_b64 or "")
    public_bytes = _b64decode(public_key_b64)
    if algorithm == "ed25519":
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, message)
    elif algorithm == "p256":
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_bytes)
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError(f"unsupported key algorithm: {algorithm}")


async def verify_signed_request(
    request: Request,
    *,
    store: SQLiteStore,
    settings: Settings,
) -> VerifiedDevice:
    request_id = request.headers.get("X-Request-Id") or new_id("req")
    device_id = request.headers.get(DEVICE_ID_HEADER)
    timestamp = request.headers.get(TIMESTAMP_HEADER)
    nonce = request.headers.get(NONCE_HEADER)
    signature = request.headers.get(SIGNATURE_HEADER)
    _ = request.headers.get(KEY_ID_HEADER)

    if not all([device_id, timestamp, nonce, signature]):
        _audit_auth_failure(
            store,
            settings,
            request,
            request_id=request_id,
            reason="missing_signature_headers",
            device_id=device_id,
            nonce=nonce,
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing device signature")

    try:
        device = store.get_device(device_id or "")
    except KeyError as exc:
        _audit_auth_failure(
            store,
            settings,
            request,
            request_id=request_id,
            reason="unknown_device",
            device_id=device_id,
            nonce=nonce,
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unknown device") from exc

    if device["status"] != "active":
        _audit_auth_failure(
            store,
            settings,
            request,
            request_id=request_id,
            reason="device_not_active",
            device_id=device_id,
            nonce=nonce,
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, "device is not active")

    try:
        timestamp_int = int(timestamp or "")
    except ValueError as exc:
        _audit_auth_failure(
            store,
            settings,
            request,
            request_id=request_id,
            reason="invalid_timestamp",
            device_id=device_id,
            nonce=nonce,
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid timestamp") from exc

    if abs(int(time.time()) - timestamp_int) > TIMESTAMP_TOLERANCE_SECONDS:
        _audit_auth_failure(
            store,
            settings,
            request,
            request_id=request_id,
            reason="timestamp_outside_window",
            device_id=device_id,
            nonce=nonce,
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "expired request timestamp")

    body = await request.body()
    canonical = canonical_request(
        method=request.method,
        path=_path_with_query(request),
        timestamp=timestamp or "",
        nonce=nonce or "",
        body=body,
    )
    try:
        verify_payload_signature(
            algorithm=device.get("device_key_algorithm", DEFAULT_KEY_ALGORITHM),
            public_key_b64=device["device_public_key"],
            signature_b64=signature or "",
            message=canonical.encode("utf-8"),
        )
    except (ValueError, InvalidSignature) as exc:
        _audit_auth_failure(
            store,
            settings,
            request,
            request_id=request_id,
            reason="invalid_signature",
            device_id=device_id,
            nonce=nonce,
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid device signature") from exc

    if not store.record_request_nonce(
        device_id=device_id or "",
        nonce=nonce or "",
        timestamp=timestamp_int,
    ):
        _audit_auth_failure(
            store,
            settings,
            request,
            request_id=request_id,
            reason="replayed_nonce",
            device_id=device_id,
            nonce=nonce,
        )
        # Also a 409, and it used to be indistinguishable from an approval
        # conflict at the client: the phone said "That decision was already
        # recorded" for a request that never reached approval logic at all. A
        # replay is retryable with a fresh nonce; an approval conflict is not.
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={
                "error": "request_replayed",
                "message": "replayed request nonce",
            },
        )

    return VerifiedDevice(
        device_id=device["device_id"],
        node_id=device["node_id"],
        permissions=device["permissions"],
        clearance_channel=device.get("clearance_channel", "local_terminal"),
    )


def _path_with_query(request: Request) -> str:
    path = request.url.path
    if request.url.query:
        return f"{path}?{request.url.query}"
    return path


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _audit_auth_failure(
    store: SQLiteStore,
    settings: Settings,
    request: Request,
    *,
    request_id: str,
    reason: str,
    device_id: str | None,
    nonce: str | None,
) -> None:
    store.append_audit_event(
        event_type="auth_signature_failed",
        actor_type="gateway",
        actor_id="gateway",
        node_id=settings.node_id,
        request_id=request_id,
        payload_redacted={
            "reason": reason,
            "device_id": device_id,
            "method": request.method,
            "path": _path_with_query(request),
            "nonce_hash": content_hash(nonce) if nonce else None,
        },
    )
