"""
Minimal WhatsApp Cloud API webhook receiver.
GET  /webhooks/whatsapp  -> Meta verification handshake
POST /webhooks/whatsapp  -> incoming events (signature-checked, de-duplicated, logged)
"""
import hashlib
import hmac
import json
import logging
import os
from collections import deque

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse

VERIFY_TOKEN = os.environ["WHATSAPP_VERIFY_TOKEN"]  # string you invent; same value goes into Meta
APP_SECRET = os.environ["META_APP_SECRET"]          # App settings -> Basic -> App secret

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("wa-webhook")

app = FastAPI()

# In-memory de-dup of message IDs (Meta retries on slow/failed responses).
# Fine for a single Railway instance; move to Mongo/Redis when this becomes the real product.
_seen_ids: deque[str] = deque(maxlen=5000)


@app.get("/")
def health():
    return {"ok": True}


@app.get("/webhooks/whatsapp")
def verify(request: Request):
    p = request.query_params
    if p.get("hub.mode") == "subscribe" and p.get("hub.verify_token") == VERIFY_TOKEN:
        log.info("Webhook verified by Meta")
        return PlainTextResponse(p.get("hub.challenge", ""))
    log.warning("Webhook verification failed")
    raise HTTPException(status_code=403, detail="Verification failed")


def _valid_signature(body: bytes, header: str | None) -> bool:
    if not header or not header.startswith("sha256="):
        return False
    expected = hmac.new(APP_SECRET.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header.removeprefix("sha256="))


@app.post("/webhooks/whatsapp")
async def receive(request: Request):
    body = await request.body()
    if not _valid_signature(body, request.headers.get("X-Hub-Signature-256")):
        log.warning("Rejected POST with bad/missing signature")
        raise HTTPException(status_code=401, detail="Bad signature")

    payload = json.loads(body)
    for entry in payload.get("entry", []):
        for change in entry.get("changes", []):
            value = change.get("value", {})

            for msg in value.get("messages", []):
                mid = msg.get("id")
                if mid in _seen_ids:
                    log.info("Duplicate message %s skipped", mid)
                    continue
                _seen_ids.append(mid)
                text = msg.get("text", {}).get("body") if msg.get("type") == "text" else f"<{msg.get('type')}>"
                log.info("INCOMING from=%s id=%s text=%r", msg.get("from"), mid, text)

            for st in value.get("statuses", []):
                log.info("STATUS id=%s status=%s to=%s", st.get("id"), st.get("status"), st.get("recipient_id"))

    log.debug("RAW %s", json.dumps(payload))
    # Always 200 fast; heavy work (AI parsing, CRM writes) goes to a background job later.
    return {"ok": True}
