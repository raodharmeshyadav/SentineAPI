"""
SentinelAPI - Automated Test Suite
Tests OpenAPI Parser, Parameter Resolution, Response Differ, Quad-Probe Oracle,
Public Resource Declassification, 404 Masking, CLI Exit Codes, and End-to-End Scans.
"""

import pytest
import requests
import json
import uuid
from typing import Dict, Any

from backend.bola_oracle import (
    AuthorizationOracle,
    IdentityProfile,
    DecisionState,
    ConfidenceLevel,
    ResponseDiffer,
    ProbeResult,
    OracleVerdict
)
from backend.scanner_engine import OpenAPISpecParser, SensitiveDataDetector, APISecurityAuditor


# =====================================================================
# 1. PARSER & SCHEMA TESTS
# =====================================================================

def test_openapi_parser_extracts_endpoints_and_params():
    sample_spec = {
        "openapi": "3.0.0",
        "paths": {
            "/api/v1/patients/{patient_id}": {
                "get": {
                    "operationId": "getPatient",
                    "parameters": [
                        {"name": "patient_id", "in": "path", "required": True, "schema": {"type": "string"}}
                    ],
                    "responses": {"200": {"description": "OK"}}
                }
            },
            "/api/v1/reports": {
                "get": {
                    "parameters": [
                        {"name": "account_id", "in": "query", "schema": {"type": "integer"}}
                    ]
                }
            }
        }
    }
    parser = OpenAPISpecParser(sample_spec)
    endpoints = parser.get_endpoints()
    assert len(endpoints) == 2
    
    ep_map = {e["path"]: e for e in endpoints}
    assert "/api/v1/patients/{patient_id}" in ep_map
    assert "/api/v1/reports" in ep_map
    
    path_vars = parser.extract_path_variables("/api/v1/patients/{patient_id}/records/{rec_id}")
    assert path_vars == ["patient_id", "rec_id"]


def test_schema_mock_body_synthesis():
    sample_spec = {
        "components": {
            "schemas": {
                "VitalsInput": {
                    "type": "object",
                    "properties": {
                        "heart_rate": {"type": "integer", "example": 72},
                        "notes": {"type": "string", "default": "stable"}
                    },
                    "required": ["heart_rate"]
                }
            }
        }
    }
    parser = OpenAPISpecParser(sample_spec)
    schema = {"$ref": "#/components/schemas/VitalsInput"}
    body = parser.synthesize_mock_body(schema)
    assert body is not None
    assert body["heart_rate"] == 72
    assert body["notes"] == "stable"


# =====================================================================
# 2. RESPONSE DIFFER & IDENTITY ANCHOR TESTS
# =====================================================================

def test_response_differ_normalization_removes_transient_keys():
    raw_response = {
        "id": "102",
        "name": "Bob Miller",
        "timestamp": 1727218900.123,
        "request_id": "req-991823",
        "date": "2026-09-24",
        "server_time": "12:00:00",
        "clinical_data": {
            "diagnosis": "Healthy",
            "uptime": 9999
        }
    }
    normalized = ResponseDiffer.normalize_json(raw_response)
    assert "timestamp" not in normalized
    assert "request_id" not in normalized
    assert "date" not in normalized
    assert "server_time" not in normalized
    assert "uptime" not in normalized["clinical_data"]
    assert normalized["id"] == "102"
    assert normalized["name"] == "Bob Miller"


def test_recursive_identity_anchor_extraction_handles_nested_objects():
    nested_payload = {
        "patient": {
            "demographics": {
                "user_id": "102",
                "patient_name": "Bob Miller",
                "email": "bob.m@example.com"
            },
            "insurance": {
                "policy_number": "INSR-991"
            }
        },
        "order_list": [
            {"order_id": "5002", "owner_id": "102"}
        ]
    }
    anchors, paths = ResponseDiffer.extract_identity_anchors(nested_payload)
    assert "102" in anchors
    assert "bob.m@example.com" in anchors
    assert "5002" in anchors
    assert any("patient.demographics.user_id=102" in p for p in paths)
    assert any("order_list[0].order_id=5002" in p for p in paths)


def test_field_and_value_overlap_calculations():
    obj_a = {"id": "102", "name": "Bob", "dept": "Cardio", "extra": "secret"}
    obj_b = {"id": "102", "name": "Bob", "dept": "Cardio", "missing": "val"}

    field_overlap = ResponseDiffer.compute_field_overlap(obj_a, obj_b)
    # shared: id, name, dept (3 out of 4 keys of obj_b) -> 3/4 = 0.75
    assert field_overlap == 0.75

    val_overlap = ResponseDiffer.compute_value_overlap(obj_a, obj_b)
    # matching k/v: id, name, dept -> 3/4 = 0.75
    assert val_overlap == 0.75


# =====================================================================
# 3. QUAD-PROBE ORACLE DECISION TESTS
# =====================================================================

class MockResponse:
    def __init__(self, status_code: int, json_data: Any = None, text: str = ""):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text or (json.dumps(json_data) if json_data else "")
        self.headers = {"Content-Type": "application/json"}

    def json(self):
        if self._json_data is not None:
            return self._json_data
        raise ValueError("No JSON")


def test_oracle_detects_bola_when_victim_identity_anchors_leak(monkeypatch):
    oracle = AuthorizationOracle()
    tenant_a = IdentityProfile(
        name="Alice", token="tok_a", header="Bearer tok_a", user_id="101", tenant_id="tenant_a", label="Tenant A"
    )
    tenant_b = IdentityProfile(
        name="Bob", token="tok_b", header="Bearer tok_b", user_id="102", tenant_id="tenant_b", label="Tenant B",
        identity_anchors={"102", "bob", "bob_miller"}
    )

    def mock_request(method, url, headers=None, params=None, json=None, timeout=None, allow_redirects=False):
        auth = headers.get("Authorization", "") if headers else ""
        if "tok_b" in auth:
            # Probe A: Victim baseline succeeds
            return MockResponse(200, {"patient_id": "102", "name": "Bob Miller", "diagnosis": "Hypertension"})
        elif "tok_a" in auth:
            if "control" in url:
                # Probe D: Attacker control succeeds
                return MockResponse(200, {"patient_id": "101", "name": "Alice Walker", "diagnosis": "Normal"})
            else:
                # Probe B: Cross-tenant attack returns Bob's private data!
                return MockResponse(200, {"patient_id": "102", "name": "Bob Miller", "diagnosis": "Hypertension"})
        else:
            # Probe C: Anonymous baseline gets 401
            return MockResponse(401, {"error": "Authentication required"})

    monkeypatch.setattr(oracle.session, "request", mock_request)

    verdict = oracle.evaluate_authorization_boundary(
        method="GET",
        victim_target_url="http://api/patients/102",
        control_target_url="http://api/patients/control/101",
        tenant_a=tenant_a,
        tenant_b=tenant_b
    )

    assert verdict.state == DecisionState.VULNERABLE
    assert verdict.confidence == ConfidenceLevel.HIGH
    assert "102" in verdict.evidence["leaked_identity_anchors"]


def test_oracle_verifies_secure_when_attacker_blocked_with_403(monkeypatch):
    oracle = AuthorizationOracle()
    tenant_a = IdentityProfile("Alice", "tok_a", "Bearer tok_a", "101", "tenant_a", "Tenant A")
    tenant_b = IdentityProfile("Bob", "tok_b", "Bearer tok_b", "102", "tenant_b", "Tenant B")

    def mock_request(method, url, headers=None, params=None, json=None, timeout=None, allow_redirects=False):
        auth = headers.get("Authorization", "") if headers else ""
        if "tok_b" in auth:
            return MockResponse(200, {"patient_id": "102", "name": "Bob"})
        elif "tok_a" in auth:
            if "control" in url:
                return MockResponse(200, {"patient_id": "101", "name": "Alice"})
            else:
                # Target blocks Alice with 403 Forbidden!
                return MockResponse(403, {"error": "Access Denied"})
        else:
            return MockResponse(401, {"error": "Token missing"})

    monkeypatch.setattr(oracle.session, "request", mock_request)

    verdict = oracle.evaluate_authorization_boundary(
        method="GET",
        victim_target_url="http://api/patients/102",
        control_target_url="http://api/patients/control/101",
        tenant_a=tenant_a,
        tenant_b=tenant_b
    )

    assert verdict.state == DecisionState.SECURE
    assert verdict.confidence == ConfidenceLevel.HIGH
    assert "Zero-Trust Authorization strictly enforced" in verdict.reason


def test_oracle_declassifies_public_resource_when_anonymous_payload_matches(monkeypatch):
    oracle = AuthorizationOracle()
    tenant_a = IdentityProfile("Alice", "tok_a", "Bearer tok_a", "101", "tenant_a", "Tenant A")
    tenant_b = IdentityProfile("Bob", "tok_b", "Bearer tok_b", "102", "tenant_b", "Tenant B")

    doctor_data = {"doctor_id": "doc_1", "name": "Dr. Sarah Adams", "specialty": "Cardiology"}

    def mock_request(method, url, headers=None, params=None, json=None, timeout=None, allow_redirects=False):
        # All requests (victim, anonymous, attacker) return the public catalog
        return MockResponse(200, doctor_data)

    monkeypatch.setattr(oracle.session, "request", mock_request)

    verdict = oracle.evaluate_authorization_boundary(
        method="GET",
        victim_target_url="http://api/doctors/doc_1",
        control_target_url="http://api/doctors/doc_1",
        tenant_a=tenant_a,
        tenant_b=tenant_b
    )

    assert verdict.state == DecisionState.PUBLIC_OR_SHARED
    assert verdict.confidence == ConfidenceLevel.HIGH
    assert "public/shared" in verdict.reason.lower()


def test_oracle_identifies_secure_masked_404_authorization(monkeypatch):
    oracle = AuthorizationOracle()
    tenant_a = IdentityProfile("Alice", "tok_a", "Bearer tok_a", "101", "tenant_a", "Tenant A")
    tenant_b = IdentityProfile("Bob", "tok_b", "Bearer tok_b", "102", "tenant_b", "Tenant B")

    def mock_request(method, url, headers=None, params=None, json=None, timeout=None, allow_redirects=False):
        auth = headers.get("Authorization", "") if headers else ""
        if "tok_b" in auth:
            # Resource exists for victim
            return MockResponse(200, {"record_id": "rec_102", "data": "private"})
        elif "tok_a" in auth:
            if "control" in url:
                return MockResponse(200, {"record_id": "rec_101", "data": "private"})
            else:
                # Securely returns 404 to unauthorized user
                return MockResponse(404, {"error": "Not Found"})
        else:
            return MockResponse(404, {"error": "Not Found"})

    monkeypatch.setattr(oracle.session, "request", mock_request)

    verdict = oracle.evaluate_authorization_boundary(
        method="GET",
        victim_target_url="http://api/masked-records/rec_102",
        control_target_url="http://api/masked-records/rec_101",
        tenant_a=tenant_a,
        tenant_b=tenant_b
    )

    assert verdict.state == DecisionState.SECURE
    assert verdict.evidence.get("is_masked_authorization") is True


# =====================================================================
# 4. SENSITIVE DATA DETECTOR TESTS
# =====================================================================

def test_sensitive_data_detector_identifies_credentials():
    payload = {
        "user": {
            "username": "alice",
            "password_hash": "$2b$12$e8yO/3d2XG4XjQ7M0RzIue1bH29vKzLopQ9.g3nUv7xWp",
            "ssn": "452-88-9102",
            "api_key": "sk_live_sec_991823_prod_ak"
        },
        "system": {
            "db": "postgres://admin:secret@db.internal:5432/core"
        }
    }
    findings = SensitiveDataDetector.scan_payload(payload)
    labels = [f["label"] for f in findings]
    assert any("Bcrypt Password Hash" in l for l in labels)
    assert any("Social Security Number" in l for l in labels)
    assert any("Live Production API Secret Key" in l for l in labels)
    assert any("PostgreSQL Database Connection URI" in l for l in labels)


# =====================================================================
# 5. LIVE SANDBOX END-TO-END INTEGRATION TESTS
# =====================================================================

def test_vulnerable_sandbox_is_detected_with_real_findings():
    """Confirms live Vulnerable API (:8001) is audited and finds BOLA and Data Exposure."""
    try:
        r = requests.get("http://127.0.0.1:8001/openapi.json", timeout=2)
        if r.status_code != 200:
            pytest.skip("Vulnerable API :8001 is not running locally.")
    except Exception:
        pytest.skip("Vulnerable API :8001 is not running locally.")

    spec = r.json()
    auditor = APISecurityAuditor("http://127.0.0.1:8001", spec)
    report = auditor.run_audit()

    assert report["score"] < 50
    assert report["grade"] == "F"
    assert report["critical_count"] >= 5

    categories = [f["category"] for f in report["findings"]]
    assert any("Broken Object Level Authorization" in c for c in categories)
    assert any("Broken Object Property Level Authorization" in c for c in categories)


def test_hardened_sandbox_passes_with_zero_bola_findings():
    """Confirms live Hardened API (:8002) returns zero BOLA vulnerabilities."""
    try:
        r = requests.get("http://127.0.0.1:8002/openapi.json", timeout=2)
        if r.status_code != 200:
            pytest.skip("Hardened API :8002 is not running locally.")
    except Exception:
        pytest.skip("Hardened API :8002 is not running locally.")

    spec = r.json()
    auditor = APISecurityAuditor("http://127.0.0.1:8002", spec)
    report = auditor.run_audit()

    assert report["score"] >= 95
    assert report["grade"] == "A+"
    assert report["critical_count"] == 0

    categories = [f["category"] for f in report["findings"]]
    assert not any("Broken Object Level Authorization" in c for c in categories)


def test_exploit_endpoint_does_not_flag_healthy_status_as_leak():
    """Confirms that GET /api/v1/health returning 200 OK is NOT classified as a leak."""
    try:
        r = requests.post(
            "http://127.0.0.1:8000/api/exploit/execute",
            json={
                "method": "GET",
                "url": "http://127.0.0.1:8001/api/v1/health",
                "auth_header": "Bearer tok_alice_9981a"
            },
            timeout=3
        )
        if r.status_code != 200:
            pytest.skip("Server :8000 is not running.")
    except Exception:
        pytest.skip("Server :8000 is not running.")

    data = r.json()
    assert data["status_code"] == 200
    assert data["is_leaked"] is False  # Must NOT be classified as leaked!
    assert len(data.get("matched_victim_anchors", [])) == 0
