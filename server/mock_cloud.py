"""Mock DLP management backend for local development.

Endpoints used by DlpAgent:
  GET  /api/v1/policy?version=N&device_id=X  -> 200 policy JSON, or 304 if version matches
  POST /api/v1/events                         <- {"device_id": ..., "events": [...]}
  WS   /ws?device_id=X                        -> {"type": "policy_updated", "version": N}

Admin endpoints for trying it out:
  PUT  /api/v1/policy        replace the policy (version is bumped and pushed to agents)
  GET  /api/v1/events        recent events, newest first
  GET  /api/v1/devices       last-seen per device
  GET  /                     small live event page

Run: python server/mock_cloud.py [--port 8080]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from collections import deque
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import Body, FastAPI, HTTPException, Query, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY = ROOT / "policy" / "default_policy.json"
MAX_EVENTS = 5000

app = FastAPI(title="DLP Monitor mock cloud")


class State:
    def __init__(self) -> None:
        self.policy: dict[str, Any] = json.loads(DEFAULT_POLICY.read_text(encoding="utf-8"))
        self.events: deque[dict[str, Any]] = deque(maxlen=MAX_EVENTS)
        self.devices: dict[str, dict[str, Any]] = {}
        self.sockets: dict[str, WebSocket] = {}

    def touch(self, device_id: str, **fields: Any) -> None:
        d = self.devices.setdefault(device_id, {"device_id": device_id})
        d["last_seen"] = time.time()
        d.update(fields)


state = State()


@app.get("/api/v1/policy")
def get_policy(version: int = Query(-1), device_id: str = Query("")) -> Response:
    if device_id:
        state.touch(device_id, policy_version=version)
    if version == state.policy.get("version"):
        return Response(status_code=304)
    return Response(content=json.dumps(state.policy, ensure_ascii=False), media_type="application/json")


@app.put("/api/v1/policy")
async def put_policy(policy: dict[str, Any] = Body(...)) -> dict[str, Any]:
    if not isinstance(policy.get("rules"), list):
        raise HTTPException(400, "policy must contain a 'rules' list")
    policy["version"] = int(state.policy.get("version", 0)) + 1
    state.policy = policy
    await broadcast({"type": "policy_updated", "version": policy["version"]})
    return {"version": policy["version"], "notified": len(state.sockets)}


@app.post("/api/v1/events")
def post_events(payload: dict[str, Any] = Body(...)) -> dict[str, int]:
    device_id = str(payload.get("device_id", "unknown"))
    events = payload.get("events", [])
    state.touch(device_id)
    received_at = time.time()
    for e in events:
        e["device_id"] = device_id
        e["received_at"] = received_at
        state.events.append(e)
        if e.get("kind") == "violation":
            hits = ", ".join(f"{m['detector']} x{m['count']}" for m in e.get("matches", []))
            print(f"[VIOLATION] {device_id} {e.get('rule_id')} {e.get('target')} ({hits})", flush=True)
    return {"accepted": len(events)}


@app.get("/api/v1/events")
def list_events(limit: int = Query(100, le=MAX_EVENTS), kind: str | None = None) -> list[dict[str, Any]]:
    items = [e for e in reversed(state.events) if kind is None or e.get("kind") == kind]
    return items[:limit]


@app.get("/api/v1/devices")
def list_devices() -> list[dict[str, Any]]:
    return [{**d, "connected": d["device_id"] in state.sockets} for d in state.devices.values()]


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket, device_id: str = Query("unknown")) -> None:
    await ws.accept()
    previous = state.sockets.get(device_id)
    state.sockets[device_id] = ws
    state.touch(device_id)
    print(f"[ws] {device_id} connected", flush=True)
    if previous is not None:
        await _close_quietly(previous)
    try:
        while True:
            await ws.receive_text()  # agents don't send; this just detects disconnects
    except WebSocketDisconnect:
        pass
    finally:
        if state.sockets.get(device_id) is ws:
            del state.sockets[device_id]
        print(f"[ws] {device_id} disconnected", flush=True)


async def broadcast(message: dict[str, Any]) -> None:
    text = json.dumps(message)
    results = await asyncio.gather(*(s.send_text(text) for s in state.sockets.values()), return_exceptions=True)
    for r in results:
        if isinstance(r, Exception):
            print(f"[ws] push failed: {r}", flush=True)


async def _close_quietly(ws: WebSocket) -> None:
    try:
        await ws.close()
    except Exception:
        pass


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return INDEX_HTML


INDEX_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>DLP mock cloud</title>
<style>
 body{font:14px system-ui,sans-serif;margin:16px;background:#fafafa;color:#222}
 table{border-collapse:collapse;width:100%} td,th{border-bottom:1px solid #ddd;padding:4px 8px;text-align:left}
 tr.violation{background:#ffe1e1} code{font-size:12px}
</style></head><body>
<h2>DLP mock cloud</h2>
<p id="devices"></p>
<table><thead><tr><th>Time</th><th>Device</th><th>Kind</th><th>Rule</th><th>Process</th><th>Target</th><th>Details</th></tr></thead>
<tbody id="rows"></tbody></table>
<script>
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
async function refresh() {
  const [events, devices] = await Promise.all([fetch('/api/v1/events?limit=200').then(r => r.json()),
                                               fetch('/api/v1/devices').then(r => r.json())]);
  document.getElementById('devices').textContent = 'Devices: ' + (devices.map(d =>
      `${d.device_id} (${d.connected ? 'push connected' : 'offline'}, policy v${d.policy_version ?? '?'})`).join(', ') || 'none');
  document.getElementById('rows').innerHTML = events.map(e => `<tr class="${esc(e.kind)}">
    <td>${new Date(e.time_ms).toLocaleTimeString()}</td><td>${esc(e.device_id)}</td><td>${esc(e.kind)}</td>
    <td>${esc(e.rule_name)}</td><td>${esc((e.image || '').split('\\\\').pop())} ${e.pid || ''}</td>
    <td><code>${esc(e.target)}</code></td>
    <td>${esc((e.matches || []).map(m => m.detector + ' x' + m.count + ' ' + (m.samples || []).join(' ')).join('; ') || e.message)}</td></tr>`).join('');
}
refresh(); setInterval(refresh, 3000);
</script></body></html>"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
