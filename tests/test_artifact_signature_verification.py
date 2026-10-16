"""JWS checks bind exact bytes to configured public keys, never publisher claims."""

import base64
import copy
import json

import pytest
from joserfc import jwk, jws
from pydantic import ValidationError

from dtvp.config import Settings
from dtvp.knowledge.signature_verification import (
    MAX_ARTIFACT_BYTES,
    TrustPolicyConflict,
    validate_trust_policy,
    verify_artifact_signature,
)
from dtvp.storage import canonical, digest


@pytest.fixture(scope="module")
def signing_keys():
    return {
        "ES256": jwk.ECKey.generate_key("P-256"),
        "ES384": jwk.ECKey.generate_key("P-384"),
        "RS256": jwk.RSAKey.generate_key(2048),
        "PS256": jwk.RSAKey.generate_key(2048),
        "Ed25519": jwk.OKPKey.generate_key("Ed25519"),
    }


def policy_for(key, algorithm="ES256", project="project-1"):
    public = key.as_dict()
    public["kid"] = "supplier-signing-1"
    return [
        {"subject": "supplier-A", "project_ids": [project], "algorithm": algorithm, "jwk": public}
    ]


def sign(key, raw, algorithm="ES256", **headers):
    registry = jws.JWSRegistry(algorithms=[algorithm])
    registry.max_payload_length = MAX_ARTIFACT_BYTES
    return jws.serialize_compact(
        {"alg": algorithm, "kid": "supplier-signing-1", **headers},
        raw,
        key,
        algorithms=[algorithm],
        registry=registry,
    )


def verify(raw, compact, policy, **changes):
    values = {
        "expected_artifact_sha256": digest(raw),
        "trusted_subject": "supplier-A",
        "project_id": "project-1",
        "trust_policy": policy,
    }
    values.update(changes)
    return verify_artifact_signature(raw, compact, **values)


@pytest.mark.parametrize("algorithm", ["ES256", "ES384", "RS256", "PS256", "Ed25519"])
def test_standard_jws_verifies_only_exact_bytes_under_scoped_public_key(algorithm, signing_keys):
    key = signing_keys[algorithm]
    raw = b'{ "document": "exact source bytes", "version": 1 }\n'
    policy = policy_for(key, algorithm)
    report = verify(raw, sign(key, raw, algorithm), policy)
    assert report["verified"] is True
    assert report["configured_signer_subject"] == "supplier-A"
    assert report["public_key_thumbprint"] == key.thumbprint()
    assert report["payload_sha256"] == report["expected_artifact_sha256"] == digest(raw)
    assert report["trust_policy_sha256"] == digest(canonical(policy))
    assert report["committed"] is False
    assert report["report_digest"] == digest(
        canonical({key: value for key, value in report.items() if key != "report_digest"})
    )
    assert "producer completeness" in " ".join(report["limitations"])


def test_payload_above_library_default_remains_bounded_and_supported(signing_keys):
    key = signing_keys["ES256"]
    raw = b"x" * 128001
    assert verify(raw, sign(key, raw), policy_for(key))["verified"]


@pytest.mark.parametrize(
    "change",
    ["artifact", "expected_sha", "subject", "project", "signature", "wrong_key", "missing_keys"],
)
def test_changed_bytes_or_untrusted_scope_never_verifies(change, signing_keys):
    key = signing_keys["ES256"]
    raw = b'{"sbom":"original"}\n'
    compact = sign(key, raw)
    policy = policy_for(key)
    kwargs = {}
    if change == "artifact":
        raw = b'{"sbom": "original"}\n'
    elif change == "expected_sha":
        kwargs["expected_artifact_sha256"] = "0" * 64
    elif change == "subject":
        kwargs["trusted_subject"] = "forged-publisher"
    elif change == "project":
        kwargs["project_id"] = "other-project"
    elif change == "signature":
        header, payload, signature = compact.split(".")
        signature = ("a" if signature[0] != "a" else "b") + signature[1:]
        compact = ".".join((header, payload, signature))
    elif change == "wrong_key":
        policy = policy_for(jwk.ECKey.generate_key("P-256"))
    else:
        policy = []
    report = verify(raw, compact, policy, **kwargs)
    assert report["verified"] is False
    assert "configured_signer_subject" not in report


def replace_header(compact, header):
    _, payload, signature = compact.split(".")
    encoded = base64.urlsafe_b64encode(header).decode().rstrip("=")
    return ".".join((encoded, payload, signature))


@pytest.mark.parametrize(
    "header",
    [
        {"alg": "none", "kid": "supplier-signing-1"},
        {"alg": "HS256", "kid": "supplier-signing-1"},
        {"alg": "ES256", "kid": "supplier-signing-1", "jku": "https://attacker.invalid/key"},
        {"alg": "ES256", "kid": "supplier-signing-1", "jwk": {"kty": "EC"}},
        {"alg": "ES256", "kid": "supplier-signing-1", "x5u": "https://attacker.invalid/cert"},
        {"alg": "ES256", "kid": "supplier-signing-1", "crit": ["b64"], "b64": False},
    ],
)
def test_request_headers_cannot_supply_trust_or_change_verification_rules(header, signing_keys):
    key = signing_keys["ES256"]
    raw = b"payload"
    compact = replace_header(sign(key, raw), json.dumps(header).encode())
    assert not verify(raw, compact, policy_for(key))["verified"]


@pytest.mark.parametrize(
    "kind", ["duplicate", "detached", "json", "invalid64", "padding", "huge_header"]
)
def test_unsupported_serializations_and_ambiguous_headers_fail_closed(kind, signing_keys):
    key = signing_keys["ES256"]
    raw = b"payload"
    compact = sign(key, raw)
    if kind == "duplicate":
        compact = replace_header(
            compact, b'{"alg":"ES256","kid":"supplier-signing-1","alg":"none"}'
        )
    elif kind == "detached":
        header, _, signature = compact.split(".")
        compact = header + ".." + signature
    elif kind == "json":
        compact = json.dumps({"payload": "cGF5bG9hZA", "signatures": []})
    elif kind == "invalid64":
        compact = "?.?.?"
    elif kind == "padding":
        compact = compact.split(".")[0] + "=.cGF5bG9hZA.signature"
    else:
        compact = "a" * 12000 + ".cGF5bG9hZA.signature"
    assert not verify(raw, compact, policy_for(key))["verified"]


@pytest.mark.parametrize(
    "change",
    [
        "private",
        "symmetric",
        "remote",
        "duplicate",
        "wildcard",
        "use",
        "algorithm",
        "scope",
        "curve",
    ],
)
def test_deployment_policy_rejects_unsafe_or_ambiguous_keys_at_startup(change, signing_keys):
    policy = policy_for(signing_keys["ES256"])
    if change == "private":
        policy[0]["jwk"] = signing_keys["ES256"].as_dict(private=True)
        policy[0]["jwk"]["kid"] = "supplier-signing-1"
    elif change == "symmetric":
        policy[0]["jwk"] = {"kty": "oct", "k": "c2VjcmV0", "kid": "key"}
    elif change == "remote":
        policy[0]["jwk"]["jku"] = "https://attacker.invalid/key"
    elif change == "duplicate":
        policy.append(copy.deepcopy(policy[0]))
    elif change == "wildcard":
        policy[0]["project_ids"] = ["*"]
    elif change == "use":
        policy[0]["jwk"]["key_ops"] = ["sign", "verify"]
    elif change == "algorithm":
        policy[0]["algorithm"] = "HS256"
    elif change == "scope":
        policy[0]["project_ids"] = []
    else:
        policy[0]["algorithm"] = "ES384"
    with pytest.raises(ValueError):
        validate_trust_policy(policy)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, playground=True, evidence_jws_trust=policy)


def test_explicit_policy_pin_rejects_rotation_and_policy_change(signing_keys):
    key = signing_keys["ES256"]
    raw = b"payload"
    policy = policy_for(key)
    old_pin = digest(canonical(policy))
    policy[0]["project_ids"].append("new-project")
    with pytest.raises(TrustPolicyConflict):
        verify(raw, sign(key, raw), policy, expected_trust_policy_sha256=old_pin)


def test_verification_limits_reject_oversized_or_empty_artifact(signing_keys):
    key = signing_keys["ES256"]
    for raw in (b"", b"x" * (MAX_ARTIFACT_BYTES + 1)):
        with pytest.raises(ValueError, match="8 MiB"):
            verify(raw, "x.x.x", policy_for(key))


def test_readonly_api_uses_settings_keys_not_client_input_and_keeps_journal_unchanged(
    analyst, app, signing_keys
):
    key = signing_keys["ES256"]
    project = analyst.get("/api/v2/projects").json()[0]["id"]
    policy = policy_for(key, project=project)
    foreign = policy_for(signing_keys["ES384"], "ES384", "other-project")[0]
    foreign["jwk"]["kid"] = "other-scope-key"
    policy.append(foreign)
    app.state.settings.evidence_jws_trust = policy
    before = app.state.knowledge.references()
    path = f"/api/v3/projects/{project}/evidence"
    plan = analyst.get(path + "/signature-policy")
    assert plan.status_code == 200
    assert len(plan.json()["keys"]) == 1
    assert "other-scope-key" not in plan.text
    raw = b'{"exact":"source bytes"}\n'
    fields = {
        "expected_artifact_sha256": digest(raw),
        "trusted_subject": "supplier-A",
        "expected_trust_policy_sha256": plan.json()["trust_policy_sha256"],
    }
    files = {"file": ("artifact.json", raw), "signature": ("artifact.jws", sign(key, raw))}
    response = analyst.post(path + "/signature-verification", data=fields, files=files)
    assert response.status_code == 200, response.text
    assert response.json()["verified"] is True
    assert app.state.knowledge.references() == before
    fields["expected_trust_policy_sha256"] = "0" * 64
    assert (
        analyst.post(path + "/signature-verification", data=fields, files=files).status_code == 409
    )
    assert (
        analyst.post(
            "/api/v3/projects/unknown/evidence/signature-verification", data=fields, files=files
        ).status_code
        == 404
    )


def test_deeply_nested_protected_header_is_rejected_without_recursion_error(signing_keys):
    key = signing_keys["ES256"]
    raw = b"payload"
    nested = b'{"alg":' + b"[" * 1500 + b'"ES256"' + b"]" * 1500 + b',"kid":"supplier-signing-1"}'
    compact = replace_header(sign(key, raw), nested)
    report = verify(raw, compact, policy_for(key))
    assert report["verified"] is False
    assert report["diagnostic"] == "invalid_compact_jws_or_signature"
