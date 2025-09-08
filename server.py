from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import asyncio, json

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
queue: asyncio.Queue = asyncio.Queue()

@app.post("/ingest")
async def ingest(payload: list[dict]):
    for rec in payload:
        await queue.put(rec)
    return {"ok": True, "n": len(payload)}

@app.get("/events")
async def events():
    async def gen():
        while True:
            rec = await queue.get()
            yield f"data: {json.dumps(rec)}\n\n"
    return StreamingResponse(gen(), media_type="text/event-stream")
