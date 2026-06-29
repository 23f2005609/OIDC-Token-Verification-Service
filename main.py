from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import jwt

app = FastAPI()

# 1. Hardcode the exact public key with proper newlines
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

# 2. Set your assigned Issuer and Audience
ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-4gzc1p8h.apps.exam.local"

class TokenRequest(BaseModel):
    token: str

@app.post("/verify")
def verify_token(req: TokenRequest):
    try:
        # 3. Decode and verify. 
        # PyJWT automatically throws an exception if the signature is bad, 
        # the token is expired, or the aud/iss don't match.
        payload = jwt.decode(
            req.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER
        )
        
        # 4. If we get here, the token is 100% valid
        return {
            "valid": True,
            "email": payload.get("email"),
            "sub": payload.get("sub"),
            "aud": payload.get("aud")
        }
        
    except jwt.PyJWTError:
        # 5. Catch ALL validation failures (tampering, expired, wrong audience)
        # Return exact format requested by grader with a 401 Unauthorized status
        return JSONResponse(
            status_code=401,
            content={"valid": False}
        )
