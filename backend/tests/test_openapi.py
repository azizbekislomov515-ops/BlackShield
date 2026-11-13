import json
from pathlib import Path

from app.cli import openapi_document

COMMITTED = Path(__file__).resolve().parents[2] / "docs" / "openapi.json"


def test_committed_openapi_document_is_current() -> None:
    """Regenerate with: blackshield-signatures openapi --output ../docs/openapi.json"""
    assert COMMITTED.read_text(encoding="utf-8") == openapi_document()


def test_openapi_documents_v1_and_auth() -> None:
    spec = json.loads(openapi_document())

    assert set(spec["paths"]) >= {
        "/v1/signatures/version",
        "/v1/signatures/delta",
        "/v1/signatures/full",
        "/v1/reputation/lookup",
    }
    assert set(spec["components"]["securitySchemes"]) == {"ApiKey", "Bearer"}
    full = spec["paths"]["/v1/signatures/full"]["get"]["responses"]["200"]
    assert "application/x-ndjson" in full["content"]
