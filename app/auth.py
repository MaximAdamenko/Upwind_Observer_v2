from fastapi import HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from app.config import settings

_bearer = HTTPBearer()


def verify_api_key(credentials: HTTPAuthorizationCredentials = Security(_bearer)) -> str:
    if credentials.credentials != settings.API_KEY:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
    return credentials.credentials
