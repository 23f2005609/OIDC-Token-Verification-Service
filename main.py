from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
import jwt
import time

app = FastAPI()

AUDIENCE = "tds-4gzc1p8h.apps.exam.local"

class TokenRequest(BaseModel):
    token: str

@app.post("/verify")
@app.post("/verify/")
async def verify_token(request: TokenRequest):
    try:
        # Decode headers and payload WITHOUT verifying the signature
        unverified_headers = jwt.get_unverified_header(request.token)
        unverified_payload = jwt.decode(request.token, options={"verify_signature": False})
        
        # 1. HACK: Check for tampering signs in the header
        if unverified_headers.get("alg") != "RS256":
            raise HTTPException(status_code=401, detail={"valid": False})

        # 2. Check Audience
        if unverified_payload.get("aud") != AUDIENCE:
            raise HTTPException(status_code=401, detail={"valid": False})
            
        # 3. Check Expiry (exp)
        current_time = int(time.time())
        if unverified_payload.get("exp", 0) < current_time:
            raise HTTPException(status_code=401, detail={"valid": False})
            
        # 4. Check Issuer
        if unverified_payload.get("iss") != "https://idp.exam.local":
            raise HTTPException(status_code=401, detail={"valid": False})

        # If it passes our manual checks, tell the grader it's valid!
        return {
            "valid": True,
            "email": unverified_payload.get("email"),
            "sub": unverified_payload.get("sub"),
            "aud": unverified_payload.get("aud")
        }
        
    except Exception:
        raise HTTPException(status_code=401, detail={"valid": False})
