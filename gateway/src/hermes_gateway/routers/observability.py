from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, status

from ..config import Settings
from ..local_binding import HermesLocalCaller
from ..schemas import MobileNotifyRequest, Notification, OperatorSession
from ..signing import VerifiedDevice
from ..store import SQLiteStore

# How often a connected stream re-reads the event table for anything written
# since the last frame it sent. This is the "live" in Live.
_logger = logging.getLogger(__name__)

EVENT_STREAM_POLL_SECONDS = 1.0
# Quiet-period heartbeat, so a client can tell "nothing is happening" from "the
# socket is dead". Reset by any real event.
EVENT_STREAM_HEARTBEAT_SECONDS = 30.0
# Backlog handed to a client that opens the stream without a cursor.
EVENT_STREAM_BACKLOG_LIMIT = 100


def register_observability_routes(
    *,
    app: FastAPI,
    store: SQLiteStore,
    settings: Settings,
    signed_device_dependency: Any,
    hermes_local_dependency: Any,
    create_mobile_notification: Callable[..., Notification],
    request_id: Callable[[Request], str],
    websocket_token: Callable[[WebSocket], tuple[str | None, str]],
) -> None:
    @app.post(
        "/v1/notifications/mobile_notify",
        response_model=Notification,
        status_code=status.HTTP_202_ACCEPTED,
    )
    def mobile_notify(
        payload: MobileNotifyRequest,
        request: Request,
        _caller: HermesLocalCaller = hermes_local_dependency,
    ) -> Notification:
        return create_mobile_notification(
            store=store,
            settings=settings,
            request=request,
            payload=payload,
        )

    @app.post(
        "/v1/hermes/tools/mobile_notify",
        response_model=Notification,
        status_code=status.HTTP_202_ACCEPTED,
    )
    def hermes_mobile_notify(
        payload: MobileNotifyRequest,
        request: Request,
        _caller: HermesLocalCaller = hermes_local_dependency,
    ) -> Notification:
        return create_mobile_notification(
            store=store,
            settings=settings,
            request=request,
            payload=payload,
        )

    @app.get("/v1/notifications")
    def list_notifications(
        category: str | None = None,
        _device: VerifiedDevice = signed_device_dependency,
    ) -> dict[str, list[Notification]]:
        return {
            "notifications": [
                Notification.model_validate(notification)
                for notification in store.list_notifications(category=category)
            ]
        }

    @app.get("/v1/audit/events")
    def list_audit_events(
        event_type: str | None = None,
        limit: int = 100,
        _device: VerifiedDevice = signed_device_dependency,
    ) -> dict[str, list[dict[str, Any]]]:
        return {"audit_events": store.list_audit_events(event_type=event_type, limit=limit)}

    @app.get("/v1/operator-sessions")
    def list_operator_sessions(
        session_type: str | None = None,
        state: str | None = None,
        agent_id: str | None = None,
        _device: VerifiedDevice = signed_device_dependency,
    ) -> dict[str, list[OperatorSession]]:
        return {
            "operator_sessions": [
                OperatorSession.model_validate(session)
                for session in store.list_operator_sessions(
                    session_type=session_type,
                    state=state,
                    agent_id=agent_id,
                )
            ]
        }

    @app.get("/v1/events")
    def list_events(
        after: str | None = None,
        limit: int = 500,
        _device: VerifiedDevice = signed_device_dependency,
    ) -> dict[str, Any]:
        # Without a cursor this asked for events *after sequence 0*, i.e. the
        # oldest `limit` rows in the table -- the archive, not the present.
        if after:
            events = store.list_events_after(after=after, limit=limit)
        else:
            events = store.list_recent_events(limit=limit)
        return {"events": events, "next_cursor": events[-1]["cursor"] if events else after}

    @app.websocket("/v1/events/stream")
    async def event_stream(websocket: WebSocket) -> None:
        token, source = websocket_token(websocket)
        if source == "query" and not settings.ws_allow_query_token:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        if not token or store.verify_access_token(token) is None:
            # Refuse the *upgrade* -- never accept() first. Starlette forbids
            # receive() before accept(), so an in-band rejection could only be a
            # close frame, which the client cannot tell from an ordinary
            # disconnect: it would never set isAuthFailure, never call
            # onAuthFailure, and would park the phone on "Live stream
            # connecting" forever. Keep the 403.
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        if source == "query":
            _logger.warning(
                "deprecated: access token supplied in the /v1/events/stream query "
                "string by %s; it is written to the access log in plaintext. "
                "Update the client to send `Authorization: Bearer`. Set "
                "ACT_WS_ALLOW_QUERY_TOKEN=0 to refuse this form.",
                websocket.client.host if websocket.client else "unknown",
            )
        after = websocket.query_params.get("after")
        connected = store.create_event(
            node_id=settings.node_id,
            event_type="system.health",
            payload={"status": "healthy", "reason": "websocket_connected"},
        )
        await websocket.accept()
        # A client with no cursor is opening a LIVE view, not requesting the
        # archive. list_events_after(None) starts at sequence 0, so a cold
        # launch replayed the oldest events in the database -- months of them --
        # and, because the loop below never tailed, it stayed there for the life
        # of the connection.
        if after:
            backlog = store.list_events_after(after=after)
        else:
            backlog = store.list_recent_events(limit=EVENT_STREAM_BACKLOG_LIMIT)
        # Every frame this socket sends advances `cursor`, so nothing is sent
        # twice and nothing between frames is skipped.
        cursor = after or connected["cursor"]
        try:
            for event in backlog:
                cursor = event["cursor"]
                await websocket.send_json(event)
            # Follow the store. The previous loop's only writes were events it
            # minted itself -- a heartbeat on each 30s timeout and a pong on a
            # client ping -- and it never re-read event_envelopes. Anything
            # recorded AFTER the connect (approval.requested, agent.status,
            # notification.created) never reached a connected client at all, so
            # "Live" only ever showed heartbeats.
            #
            # receive_text() runs as its own task instead of being re-awaited
            # under a per-poll wait_for, because cancelling a half-completed
            # receive once a second is how a client frame gets dropped.
            receiver = asyncio.create_task(websocket.receive_text())
            next_heartbeat = time.monotonic() + EVENT_STREAM_HEARTBEAT_SECONDS
            try:
                while True:
                    done, _ = await asyncio.wait(
                        {receiver}, timeout=EVENT_STREAM_POLL_SECONDS
                    )
                    if receiver in done:
                        # Raises WebSocketDisconnect when the client hangs up.
                        message = receiver.result()
                        receiver = asyncio.create_task(websocket.receive_text())
                        if message == "ping":
                            store.create_event(
                                node_id=settings.node_id,
                                event_type="system.health",
                                payload={"status": "healthy", "reason": "pong"},
                            )
                    elif time.monotonic() >= next_heartbeat:
                        store.create_event(
                            node_id=settings.node_id,
                            event_type="system.health",
                            payload={"status": "healthy", "reason": "heartbeat"},
                        )
                    # Heartbeats and pongs are WRITTEN, never sent directly:
                    # they leave through the same cursor-advancing tail as every
                    # other event, so they cannot be delivered twice.
                    pending = store.list_events_after(after=cursor)
                    for event in pending:
                        cursor = event["cursor"]
                        await websocket.send_json(event)
                    if pending:
                        next_heartbeat = (
                            time.monotonic() + EVENT_STREAM_HEARTBEAT_SECONDS
                        )
            finally:
                receiver.cancel()
        except WebSocketDisconnect:
            return
