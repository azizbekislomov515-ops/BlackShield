from fastapi import APIRouter, Depends

from app.api.v1 import reputation, rules, signatures
from app.api.v1.deps import require_api_client

router = APIRouter(prefix="/v1", dependencies=[Depends(require_api_client)])
router.include_router(signatures.router)
router.include_router(reputation.router)
router.include_router(rules.router)
