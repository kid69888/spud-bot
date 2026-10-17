# File: server.py | Python 3.11+ | FastAPI license validation server
# pip install fastapi uvicorn aiosqlite
# Run: python server.py  (listens on 0.0.0.0:8000)
# Host this on any VPS — the spoofer calls it to validate keys

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import aiosqlite
import datetime
import hashlib
import os

app     = FastAPI()
DB_PATH = "licenses.db"  # same DB as bot.py — run both on same machine

# Shared secret between server.py and PotatoSpoofer.exe
# Change this to something random, match it in PotatoSpoofer_v3.cs
API_SECRET = os.getenv("API_SECRET", "spud_change_this_secret_6767")

class ValidateRequest(BaseModel):
    key:  str
    hwid: str   # SHA256 of MachineGuid — sent by spoofer on validate

class ValidateResponse(BaseModel):
    valid:      bool
    tier:       str
    expires_at: str
    message:    str

def hwid_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()

@app.post("/validate", response_model=ValidateResponse)
async def validate(req: ValidateRequest,
                   x_api_secret: str = Header(default="")):
    if x_api_secret != API_SECRET:
        raise HTTPException(status_code=403, detail="Bad secret")

    key  = req.key.strip().upper()
    hwid = hwid_hash(req.hwid)

    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT tier,expires_at,redeemed_by,hwid,active FROM licenses"
            " WHERE key=?", (key,)) as cur:
            row = await cur.fetchone()

        if not row:
            return ValidateResponse(valid=False, tier="", expires_at="",
                                    message="Invalid key")

        tier, exp_at, redeemed_by, stored_hwid, active = row

        if not active:
            return ValidateResponse(valid=False, tier=tier, expires_at="",
                                    message="Key revoked")

        if not redeemed_by:
            return ValidateResponse(valid=False, tier=tier, expires_at="",
                                    message="Key not redeemed via Discord first")

        # HWID binding — first use after redeem binds the key to this machine
        if not stored_hwid:
            await db.execute(
                "UPDATE licenses SET hwid=? WHERE key=?", (hwid, key))
            await db.commit()
            stored_hwid = hwid

        if stored_hwid != hwid:
            return ValidateResponse(valid=False, tier=tier, expires_at="",
                                    message="HWID mismatch — key bound to different machine")

        if exp_at:
            exp = datetime.datetime.fromisoformat(exp_at)
            if datetime.datetime.utcnow() > exp:
                return ValidateResponse(valid=False, tier=tier,
                                        expires_at=exp_at,
                                        message="Key expired")

        exp_str = exp_at[:10] if exp_at else "Lifetime"
        return ValidateResponse(valid=True, tier=tier,
                                expires_at=exp_str,
                                message=f"Valid — {tier} until {exp_str}")

@app.get("/health")
async def health():
    return {"status": "potato"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=False)
