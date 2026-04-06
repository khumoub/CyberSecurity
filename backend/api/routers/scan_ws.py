from fastapi import WebSocket, WebSocketDisconnect, APIRouter
import redis.asyncio as aioredis
from core.config import settings

router = APIRouter()


@router.websocket("/ws/scan/{scan_id}")
async def stream_scan_output(websocket: WebSocket, scan_id: str):
    """
    Stream live scan output to a connected WebSocket client.
    Messages are published to Redis by worker tasks and forwarded here.
    """
    await websocket.accept()
    r = aioredis.from_url(settings.REDIS_URL)
    pubsub = r.pubsub()
    await pubsub.subscribe(f"scan_output:{scan_id}")
    try:
        async for message in pubsub.listen():
            if message["type"] == "message":
                data = message["data"]
                if isinstance(data, bytes):
                    data = data.decode()
                await websocket.send_text(data)
    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.unsubscribe(f"scan_output:{scan_id}")
        await r.aclose()
