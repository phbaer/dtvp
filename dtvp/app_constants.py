from typing import Any, TypeAlias

ResponseMap: TypeAlias = dict[int | str, dict[str, Any]]

MEDIA_TYPE_JSON = "application/json"
BACKEND_SBOM_FILENAME = "dtvp-backend-cyclonedx.json"
FRONTEND_SBOM_FILENAME = "dtvp-frontend-cyclonedx.json"
HTML_SBOM_FILENAME = "dtvp-cyclonedx.json"
TMRESCORE_NOT_CONFIGURED_DETAIL = "VScorer integration is not configured"
CODE_ANALYSIS_NOT_CONFIGURED_DETAIL = "Code analysis integration is not configured."
BAD_REQUEST_RESPONSE: ResponseMap = {400: {"description": "Bad request"}}
FORBIDDEN_RESPONSE: ResponseMap = {403: {"description": "Forbidden"}}
NOT_FOUND_RESPONSE: ResponseMap = {404: {"description": "Not found"}}
SERVICE_UNAVAILABLE_RESPONSE: ResponseMap = {
    503: {"description": "Service unavailable"}
}
