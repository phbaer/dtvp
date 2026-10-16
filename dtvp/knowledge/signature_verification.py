"""Exact-artifact RFC 7515 compact JWS checks under deployment-owned key policy."""

import base64
import json
import re
from datetime import UTC, datetime

from joserfc import jwk, jws
from joserfc.errors import JoseError

from dtvp.storage import canonical, digest

MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
MAX_JWS_BYTES = 12 * 1024 * 1024
MAX_HEADER_BYTES = 8192
ALGORITHMS = {
    "ES256": ("EC", "P-256"),
    "ES384": ("EC", "P-384"),
    "RS256": ("RSA", None),
    "PS256": ("RSA", None),
    "Ed25519": ("OKP", "Ed25519"),
}
LIMITATIONS = [
    "The configured signer label and project scope are deployment trust declarations, not independently established publisher identity.",
    "Verification binds the exact supplied artifact bytes, not a canonicalized document or an independently authenticated signing time.",
    "No embedded JSF, detached/unencoded JWS, DSSE, Sigstore, certificate chain or revocation validation is performed.",
    "No assertion of producer completeness, product/context applicability, license clearance, human approval or regulatory compliance.",
    "This read-only report does not import, approve or upgrade trust on any evidence record.",
]


class TrustPolicyConflict(ValueError):
    """The caller's pinned deployment trust policy changed."""


def _text(value, maximum=500):
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(char) < 32 for char in value)
    ):
        raise ValueError(
            "JWS trust values must be bounded nonempty text without control characters"
        )
    return value


def validate_trust_policy(policy):
    """Validate public-only keys and exact scopes before accepting deployment settings."""
    if not isinstance(policy, list) or len(policy) > 100:
        raise ValueError("JWS trust policy must contain at most 100 public keys")
    if len(canonical(policy)) > 1024 * 1024:
        raise ValueError("JWS trust policy exceeds 1 MiB")
    seen = set()
    keys = []
    for item in policy:
        if not isinstance(item, dict) or set(item) != {
            "subject",
            "project_ids",
            "algorithm",
            "jwk",
        }:
            raise ValueError(
                "JWS trust entries require subject, project_ids, algorithm and public jwk"
            )
        _text(item["subject"])
        scopes = item["project_ids"]
        if (
            not isinstance(scopes, list)
            or not 1 <= len(scopes) <= 200
            or any(not isinstance(scope, str) or not scope or "*" in scope for scope in scopes)
        ):
            raise ValueError(
                "JWS trust requires explicit bounded project scopes; wildcards are forbidden"
            )
        if len(set(scopes)) != len(scopes):
            raise ValueError("Duplicate JWS project scope")
        for scope in scopes:
            _text(scope)
        algorithm = item["algorithm"]
        if not isinstance(algorithm, str) or algorithm not in ALGORITHMS:
            raise ValueError("Unsupported JWS trust algorithm")
        public = item["jwk"]
        if not isinstance(public, dict) or len(canonical(public)) > 8192:
            raise ValueError("JWS trust requires a bounded public JWK")
        key_type, curve = ALGORITHMS[algorithm]
        fields = {"kty", "kid", "alg", "use", "key_ops"} | {
            "RSA": {"n", "e"},
            "EC": {"crv", "x", "y"},
            "OKP": {"crv", "x"},
        }[key_type]
        if set(public) - fields or public.get("kty") != key_type:
            raise ValueError(
                "JWS trust keys must be public-only, with no remote/certificate/extra fields"
            )
        kid = _text(public.get("kid"), 128)
        if kid in seen:
            raise ValueError("JWS trust key IDs must be unique")
        seen.add(kid)
        if (
            public.get("alg", algorithm) != algorithm
            or public.get("use", "sig") != "sig"
            or public.get("key_ops", ["verify"]) != ["verify"]
        ):
            raise ValueError("JWS public key usage/algorithm conflicts with deployment policy")
        if curve and public.get("crv") != curve:
            raise ValueError("JWS public key curve conflicts with deployment algorithm")
        try:
            key = jwk.import_key(public, key_type=key_type)
            if key.is_private or key_type == "RSA" and not 2048 <= key.raw_value.key_size <= 8192:
                raise ValueError("JWS RSA public key size must be between 2048 and 8192 bits")
        except (JoseError, TypeError, KeyError, AttributeError) as error:
            raise ValueError("Invalid deployment JWS public key") from error
        keys.append((item, key))
    return keys


def _decode(segment):
    if not segment or not re.fullmatch(r"[A-Za-z0-9_-]+", segment):
        raise ValueError("JWS segments must use unpadded base64url")
    raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    if base64.urlsafe_b64encode(raw).decode().rstrip("=") != segment:
        raise ValueError("Noncanonical JWS base64url segment")
    return raw


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JWS protected header member")
        result[key] = value
    return result


def verify_artifact_signature(
    raw,
    compact_jws,
    *,
    expected_artifact_sha256,
    trusted_subject,
    project_id,
    trust_policy,
    expected_trust_policy_sha256=None,
):
    """Verify with exactly one configured public key; never use request-supplied keys."""
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise ValueError("JWS artifact must contain between 1 byte and 8 MiB")
    if not isinstance(compact_jws, str) or not 1 <= len(compact_jws) <= MAX_JWS_BYTES:
        raise ValueError("Compact JWS exceeds supported 12 MiB bounds")
    _text(trusted_subject)
    _text(project_id)
    if not isinstance(expected_artifact_sha256, str) or not re.fullmatch(
        r"[0-9a-f]{64}", expected_artifact_sha256
    ):
        raise ValueError("Expected artifact SHA-256 must be lowercase hexadecimal")
    keys = validate_trust_policy(trust_policy)
    policy_sha = digest(canonical(trust_policy))
    if expected_trust_policy_sha256 is not None and expected_trust_policy_sha256 != policy_sha:
        raise TrustPolicyConflict("Deployment JWS trust policy changed; repin explicitly")
    content = {
        "format": "dtvp.artifact-signature-verification/1",
        "committed": False,
        "project_id": project_id,
        "artifact_sha256": digest(raw),
        "expected_artifact_sha256": expected_artifact_sha256,
        "compact_jws_sha256": digest(compact_jws.encode()),
        "trust_policy_sha256": policy_sha,
        "signature_format": "RFC7515_compact_JWS",
        "verified": False,
        "verified_at": datetime.now(UTC).isoformat(),
        "limitations": LIMITATIONS,
    }

    def result(code, **details):
        report = {**content, "diagnostic": code, **details}
        return {**report, "report_digest": digest(canonical(report))}

    if content["artifact_sha256"] != expected_artifact_sha256:
        return result("artifact_sha256_mismatch")
    if not keys:
        return result("no_deployment_trusted_keys")
    try:
        parts = compact_jws.split(".")
        if (
            len(parts) != 3
            or len(parts[0]) > (MAX_HEADER_BYTES * 4 // 3 + 4)
            or len(parts[2]) > 2048
        ):
            raise ValueError("Unsupported compact JWS dimensions")
        header_raw = _decode(parts[0])
        if len(header_raw) > MAX_HEADER_BYTES:
            raise ValueError("JWS header exceeds 8 KiB")
        header = json.loads(header_raw, object_pairs_hook=_unique_object)
        if not isinstance(header, dict) or set(header) - {"alg", "kid", "typ", "cty"}:
            return result("unsupported_protected_header")
        algorithm = _text(header.get("alg"), 128)
        kid = _text(header.get("kid"), 128)
        for optional in ("typ", "cty"):
            if optional in header:
                _text(header[optional], 256)
        if algorithm not in ALGORITHMS:
            return result("unsupported_algorithm")
        candidates = [
            (item, key)
            for item, key in keys
            if item["subject"] == trusted_subject
            and project_id in item["project_ids"]
            and item["jwk"]["kid"] == kid
            and item["algorithm"] == algorithm
        ]
        if len(candidates) != 1:
            return result("no_trusted_key_for_subject_and_project")
        if len(parts[1]) > MAX_ARTIFACT_BYTES * 4 // 3 + 4:
            return result("encoded_payload_exceeds_limit")
        payload = _decode(parts[1])
        _decode(parts[2])
        if payload != raw:
            return result("signed_payload_differs_from_artifact")
        item, key = candidates[0]
        registry = jws.JWSRegistry(algorithms=[algorithm])
        registry.max_header_length = MAX_HEADER_BYTES
        registry.max_payload_length = MAX_ARTIFACT_BYTES
        registry.max_signature_length = 1024
        verified = jws.deserialize_compact(
            compact_jws, key, algorithms=[algorithm], registry=registry
        )
        if verified.payload != raw:
            return result("signed_payload_differs_from_artifact")
        return result(
            "signature_verified",
            verified=True,
            configured_signer_subject=item["subject"],
            key_id=kid,
            algorithm=algorithm,
            public_key_thumbprint=key.thumbprint(),
            payload_sha256=digest(verified.payload),
        )
    except ValueError, TypeError, UnicodeError, RecursionError, JoseError:
        return result("invalid_compact_jws_or_signature")
