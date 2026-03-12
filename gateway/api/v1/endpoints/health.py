from datetime import datetime, timezone
from fastapi import APIRouter

router = APIRouter(tags=["Health"])

@router.get("/health")
async def health():
    return {"status": "healthy", "service": "BAC Security Gateway",
            "timestamp": datetime.now(timezone.utc).isoformat()}
