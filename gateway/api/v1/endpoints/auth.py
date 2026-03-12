from fastapi import APIRouter, HTTPException, status
from gateway.schemas.auth import LoginRequest, TokenResponse
from gateway.services.auth_service import authenticate_user, create_token_for_user

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest):
    user = await authenticate_user(body.email, body.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Incorrect email or password")
    return TokenResponse(
        access_token=create_token_for_user(user, remember_me=body.remember_me),
        username=user.username,
        role="admin" if user.is_admin else "user",
    )
