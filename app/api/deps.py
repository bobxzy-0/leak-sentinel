from fastapi import Depends, Request
from sqlalchemy.orm import Session
from typing import Optional
from app.core.database import get_db
from app.core.security import verify_token
from app.models.models import User

async def get_current_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ")[1]
    payload = verify_token(token)
    if not payload:
        return None
    user = db.query(User).filter(User.email == payload.get("sub")).first()
    return user
