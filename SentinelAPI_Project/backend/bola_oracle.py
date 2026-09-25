"""
SentinelAPI - Enterprise Authorization Decision Oracle & Quad-Probe Engine
Production-grade differential testing for BOLA/IDOR and access boundary failures.

Principles:
1. Quad-probe baseline triangulation (Victim, Attacker, Anonymous, Control).
2. Recursive ownership anchor inspection across nested schemas.
3. Multi-signal decision taxonomy (VULNERABLE, SECURE, PUBLIC_OR_SHARED, INCONCLUSIVE, BASELINE_INVALID, TRANSPORT_ERROR).
4. No hardcoded target IDs or false-certainty metrics.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Set, Tuple
import requests
import json
import time
import re
import uuid


class DecisionState(str, Enum):
    VULNERABLE = "VULNERABLE"
    SECURE = "SECURE"
    PUBLIC_OR_SHARED = "PUBLIC_OR_SHARED"
    INCONCLUSIVE = "INCONCLUSIVE"
    BASELINE_INVALID = "BASELINE_INVALID"
    TRANSPORT_ERROR = "TRANSPORT_ERROR"


class ConfidenceLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INCONCLUSIVE = "INCONCLUSIVE"


class ParameterRole(str, Enum):
    OBJECT_ID = "OBJECT_ID"
    TENANT_ID = "TENANT_ID"
    USER_ID = "USER_ID"
    PARENT_SCOPE = "PARENT_SCOPE"
    QUERY_FILTER = "QUERY_FILTER"
    UNKNOWN = "UNKNOWN"


@dataclass
class IdentityProfile:
    name: str
    token: str
    header: str
    user_id: str
    tenant_id: str
    label: str
    known_objects: Dict[str, Any] = field(default_factory=dict)
    identity_anchors: Set[str] = field(default_factory=set)

    def __post_init__(self):
        if not self.identity_anchors:
            self.identity_anchors = set()
        if self.user_id:
            self.identity_anchors.add(str(self.user_id).lower().strip())
        if self.tenant_id:
            self.identity_anchors.add(str(self.tenant_id).lower().strip())
        if self.name:
            self.identity_anchors.add(str(self.name).lower().strip())


@dataclass
class ProbeResult:
    probe_name: str
    status_code: int
    headers: Dict[str, str]
    body: Any
    latency_ms: float
    error: Optional[str] = None


@dataclass
class ResourceOwnershipEvidence:
    victim_identity_fields_found: List[str]
    attacker_received_victim_identity: bool
    leaked_anchors: List[str]
    nested_owner_paths: List[str]
    field_overlap: float
    exact_value_overlap: float
    schema_identical: bool


@dataclass
class OracleVerdict:
    state: DecisionState
    confidence: ConfidenceLevel
    reason: str
    evidence: Dict[str, Any]
    probe_results: Dict[str, ProbeResult] = field(default_factory=dict)


class ResponseDiffer:
    """Calculates deep structural and identity differentials between HTTP responses."""

    TRANSIENT_KEYS = {
        "timestamp", "time", "date", "request_id", "req_id", "trace_id",
        "correlation_id", "nonce", "uptime", "duration", "latency",
        "server_time", "version", "_t"
    }

    OWNERSHIP_FIELD_CANDIDATES = {
        "id", "user_id", "userid", "owner_id", "ownerid", "patient_id",
        "patientid", "tenant_id", "tenantid", "account_id", "accountid",
        "org_id", "organization_id", "workspace_id", "customer_id",
        "email", "username", "ssn", "policy_number", "billing_address"
    }

    @classmethod
    def normalize_json(cls, data: Any) -> Any:
        """Removes non-deterministic keys (timestamps, request IDs) for fair comparison."""
        if isinstance(data, dict):
            normalized = {}
            for k, v in data.items():
                if k.lower() in cls.TRANSIENT_KEYS:
                    continue
                normalized[k] = cls.normalize_json(v)
            return normalized
        elif isinstance(data, list):
            return [cls.normalize_json(item) for item in data]
        return data

    @classmethod
    def extract_identity_anchors(cls, data: Any, current_path: str = "") -> Tuple[Set[str], List[str]]:
        """
        Recursively extracts identity anchor values and tracks their JSON paths.
        Detects nested owners like data['patient']['owner']['user_id'].
        """
        anchors: Set[str] = set()
        paths: List[str] = []

        if isinstance(data, dict):
            for k, v in data.items():
                subpath = f"{current_path}.{k}" if current_path else k
                k_lower = k.lower().replace("-", "_")

                if any(cand in k_lower for cand in cls.OWNERSHIP_FIELD_CANDIDATES):
                    if isinstance(v, (str, int, float)) and str(v).strip():
                        val_str = str(v).lower().strip()
                        anchors.add(val_str)
                        paths.append(f"{subpath}={val_str}")

                if isinstance(v, (dict, list)):
                    sub_anchors, sub_paths = cls.extract_identity_anchors(v, subpath)
                    anchors.update(sub_anchors)
                    paths.extend(sub_paths)

        elif isinstance(data, list):
            for idx, item in enumerate(data):
                sub_anchors, sub_paths = cls.extract_identity_anchors(item, f"{current_path}[{idx}]")
                anchors.update(sub_anchors)
                paths.extend(sub_paths)

        return anchors, paths

    @classmethod
    def compute_field_overlap(cls, body_a: Any, body_b: Any) -> float:
        """Computes key-space overlap between two JSON payloads."""
        if not isinstance(body_a, dict) or not isinstance(body_b, dict):
            return 1.0 if body_a == body_b and body_a is not None else 0.0

        keys_a = set(body_a.keys())
        keys_b = set(body_b.keys())
        if not keys_b:
            return 0.0

        shared = keys_a.intersection(keys_b)
        return round(len(shared) / max(len(keys_b), 1), 3)

    @classmethod
    def compute_value_overlap(cls, body_a: Any, body_b: Any) -> float:
        """Computes exact key-value match ratio between two payloads."""
        if not isinstance(body_a, dict) or not isinstance(body_b, dict):
            return 1.0 if body_a == body_b and body_a is not None else 0.0

        matches = sum(1 for k, v in body_b.items() if body_a.get(k) == v)
        return round(matches / max(len(body_b), 1), 3)


class AuthorizationOracle:
    """
    Executes the Quad-Probe Authorization Triangulation Model.
    Deterministically differentiates between BOLA, Zero-Trust blocks, public routes, and invalid baselines.
    """

    def __init__(self, timeout: float = 3.5, session: Optional[requests.Session] = None):
        self.timeout = timeout
        self.session = session or requests.Session()

    def _execute_probe(
        self,
        name: str,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None
    ) -> ProbeResult:
        start = time.time()
        try:
            req_headers = {"Accept": "application/json"}
            if headers:
                req_headers.update(headers)

            resp = self.session.request(
                method=method,
                url=url,
                headers=req_headers,
                params=params,
                json=json_body,
                timeout=self.timeout,
                allow_redirects=False
            )
            latency = round((time.time() - start) * 1000, 2)

            body = None
            try:
                body = resp.json()
            except Exception:
                body = resp.text[:1000]

            return ProbeResult(
                probe_name=name,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=body,
                latency_ms=latency,
                error=None
            )
        except Exception as e:
            latency = round((time.time() - start) * 1000, 2)
            return ProbeResult(
                probe_name=name,
                status_code=0,
                headers={},
                body=None,
                latency_ms=latency,
                error=str(e)
            )

    def evaluate_authorization_boundary(
        self,
        method: str,
        victim_target_url: str,
        control_target_url: str,
        tenant_a: IdentityProfile,
        tenant_b: IdentityProfile,
        victim_query_params: Optional[Dict[str, Any]] = None,
        control_query_params: Optional[Dict[str, Any]] = None,
        request_body: Optional[Dict[str, Any]] = None
    ) -> OracleVerdict:
        """
        Executes Quad Probe Triangulation:
        1. Probe A (Victim Baseline): Tenant B accesses Tenant B's object.
        2. Probe B (Attacker Test): Tenant A accesses Tenant B's object.
        3. Probe C (Anonymous Baseline): Anonymous requests Tenant B's object.
        4. Probe D (Attacker Control): Tenant A accesses Tenant A's own object.
        """
        probes: Dict[str, ProbeResult] = {}

        # ---------------------------------------------------------
        # PROBE A: Victim Baseline (Ground Truth of Target Existence)
        # ---------------------------------------------------------
        headers_b = {"Authorization": tenant_b.header}
        probe_a = self._execute_probe(
            name="A_victim_baseline",
            method=method,
            url=victim_target_url,
            headers=headers_b,
            params=victim_query_params,
            json_body=request_body
        )
        probes["A_victim_baseline"] = probe_a

        if probe_a.error:
            return OracleVerdict(
                state=DecisionState.TRANSPORT_ERROR,
                confidence=ConfidenceLevel.HIGH,
                reason=f"Network transport fault during victim baseline execution: {probe_a.error}",
                evidence={"probe_error": probe_a.error},
                probe_results=probes
            )

        # Baseline Validity Check: Did the victim actually access their own resource?
        if probe_a.status_code in [404, 422, 400, 500, 502, 503]:
            return OracleVerdict(
                state=DecisionState.BASELINE_INVALID,
                confidence=ConfidenceLevel.HIGH,
                reason=(
                    f"Baseline owner request failed with HTTP {probe_a.status_code}. "
                    f"The specified resource target cannot be confirmed to exist for Tenant B."
                ),
                evidence={"victim_status": probe_a.status_code, "victim_body": probe_a.body},
                probe_results=probes
            )

        if probe_a.status_code in [401, 403]:
            return OracleVerdict(
                state=DecisionState.BASELINE_INVALID,
                confidence=ConfidenceLevel.HIGH,
                reason=f"Tenant B credentials were rejected on their own resource with HTTP {probe_a.status_code}.",
                evidence={"victim_status": probe_a.status_code},
                probe_results=probes
            )

        # ---------------------------------------------------------
        # PROBE C: Anonymous Baseline (Public Resource Declassification)
        # ---------------------------------------------------------
        probe_c = self._execute_probe(
            name="C_anonymous_baseline",
            method=method,
            url=victim_target_url,
            headers=None,  # No Authorization
            params=victim_query_params,
            json_body=request_body
        )
        probes["C_anonymous_baseline"] = probe_c

        # If anonymous request legitimately gets HTTP 200 with identical normalized data:
        if probe_c.status_code in [200, 201, 204]:
            norm_victim = ResponseDiffer.normalize_json(probe_a.body)
            norm_anon = ResponseDiffer.normalize_json(probe_c.body)

            if norm_victim == norm_anon and norm_victim is not None:
                return OracleVerdict(
                    state=DecisionState.PUBLIC_OR_SHARED,
                    confidence=ConfidenceLevel.HIGH,
                    reason=(
                        "Endpoint is intentionally public/shared. Unauthenticated requests receive "
                        "the exact same data representation as authenticated requests. NOT a BOLA vulnerability."
                    ),
                    evidence={
                        "anonymous_status": probe_c.status_code,
                        "victim_status": probe_a.status_code,
                        "payload_equivalence": True
                    },
                    probe_results=probes
                )

        # ---------------------------------------------------------
        # PROBE D: Attacker Control (Validating Tenant A Identity)
        # ---------------------------------------------------------
        headers_a = {"Authorization": tenant_a.header}
        probe_d = self._execute_probe(
            name="D_attacker_control",
            method=method,
            url=control_target_url,
            headers=headers_a,
            params=control_query_params,
            json_body=request_body
        )
        probes["D_attacker_control"] = probe_d

        if probe_d.error or probe_d.status_code in [401, 403]:
            return OracleVerdict(
                state=DecisionState.INCONCLUSIVE,
                confidence=ConfidenceLevel.MEDIUM,
                reason=(
                    f"Attacker control check failed (HTTP {probe_d.status_code}). "
                    f"Tenant A credentials or control resource ({control_target_url}) are invalid. "
                    f"Cannot differentiate authorization boundaries without valid control ground truth."
                ),
                evidence={"control_status": probe_d.status_code, "control_url": control_target_url},
                probe_results=probes
            )

        # ---------------------------------------------------------
        # PROBE B: Attacker Cross-Tenant Probe (The Core Test)
        # ---------------------------------------------------------
        probe_b = self._execute_probe(
            name="B_attacker_probe",
            method=method,
            url=victim_target_url,
            headers=headers_a,
            params=victim_query_params,
            json_body=request_body
        )
        probes["B_attacker_probe"] = probe_b

        # ---------------------------------------------------------
        # EVALUATE AUTHORIZATION BOUNDARY
        # ---------------------------------------------------------

        # Case 1: Zero-Trust Enforced (401 Unauthorized / 403 Forbidden)
        if probe_b.status_code in [401, 403]:
            return OracleVerdict(
                state=DecisionState.SECURE,
                confidence=ConfidenceLevel.HIGH,
                reason=f"Zero-Trust Authorization strictly enforced. Target server rejected cross-tenant access with HTTP {probe_b.status_code}.",
                evidence={
                    "attacker_status": probe_b.status_code,
                    "victim_status": probe_a.status_code,
                    "control_status": probe_d.status_code
                },
                probe_results=probes
            )

        # Case 2: Object Masking Policy (HTTP 404 Not Found)
        if probe_b.status_code == 404:
            # We already proved the resource exists in Probe A (victim status == 200).
            # If the server returns 404 to Tenant A, it is intentionally masking the object's existence.
            return OracleVerdict(
                state=DecisionState.SECURE,
                confidence=ConfidenceLevel.HIGH,
                reason=(
                    "Zero-Trust Authorization enforced via Masked Object Policy (HTTP 404). "
                    "The object was verified to exist for Tenant B, but server returns 404 to unauthorized Tenant A "
                    "to prevent resource enumeration."
                ),
                evidence={
                    "attacker_status": 404,
                    "victim_status": probe_a.status_code,
                    "is_masked_authorization": True
                },
                probe_results=probes
            )

        # Case 3: Cross-Tenant Access Succeeded (HTTP 200 / 201 / 204)
        if probe_b.status_code in [200, 201, 204]:
            payload_victim = probe_a.body
            payload_attacker = probe_b.body

            # Extract identity anchors
            victim_anchors, victim_paths = ResponseDiffer.extract_identity_anchors(payload_victim)
            attacker_anchors, attacker_paths = ResponseDiffer.extract_identity_anchors(payload_attacker)

            # Known anchors from Tenant B profile
            tenant_b_known = {a.lower().strip() for a in tenant_b.identity_anchors}
            # Anchors that are exclusive to Tenant B (not shared with Tenant A)
            tenant_a_known = {a.lower().strip() for a in tenant_a.identity_anchors}

            # Leaked identity anchors: Tenant B anchors appearing in Tenant A's response
            leaked_anchors = (victim_anchors.union(tenant_b_known)).intersection(attacker_anchors) - tenant_a_known

            field_overlap = ResponseDiffer.compute_field_overlap(payload_attacker, payload_victim)
            value_overlap = ResponseDiffer.compute_value_overlap(payload_attacker, payload_victim)

            evidence = {
                "victim_status": probe_a.status_code,
                "attacker_status": probe_b.status_code,
                "anonymous_status": probe_c.status_code,
                "control_status": probe_d.status_code,
                "field_overlap": field_overlap,
                "value_overlap": value_overlap,
                "leaked_identity_anchors": sorted(list(leaked_anchors)),
                "nested_owner_evidence": attacker_paths[:5]
            }

            # DETERMINATION LOGIC:
            # Sub-case 3A: Explicit Tenant B identity anchor found in Attacker response
            if leaked_anchors:
                return OracleVerdict(
                    state=DecisionState.VULNERABLE,
                    confidence=ConfidenceLevel.HIGH,
                    reason=(
                        f"CRITICAL BOLA/IDOR DETECTED: Tenant A successfully accessed private resource of Tenant B. "
                        f"Response payload explicitly exposes Tenant B identity anchors: {sorted(list(leaked_anchors))}."
                    ),
                    evidence=evidence,
                    probe_results=probes
                )

            # Sub-case 3B: High value/schema overlap without public declassification
            if field_overlap >= 0.80 and value_overlap >= 0.60:
                return OracleVerdict(
                    state=DecisionState.VULNERABLE,
                    confidence=ConfidenceLevel.HIGH,
                    reason=(
                        f"CRITICAL BOLA/IDOR DETECTED: Response schema equivalence ({field_overlap*100:.1f}% field overlap, "
                        f"{value_overlap*100:.1f}% value overlap) confirms cross-tenant data retrieval with HTTP 200 OK."
                    ),
                    evidence=evidence,
                    probe_results=probes
                )

            # Sub-case 3C: Status 200 but low/ambiguous similarity
            return OracleVerdict(
                state=DecisionState.INCONCLUSIVE,
                confidence=ConfidenceLevel.LOW,
                reason=(
                    f"Attacker received HTTP {probe_b.status_code}, but the response structure showed low correlation "
                    f"with victim data ({field_overlap*100:.1f}% overlap) and contained no verified tenant identity anchors."
                ),
                evidence=evidence,
                probe_results=probes
            )

        # Case 4: Any other unexpected status code
        return OracleVerdict(
            state=DecisionState.INCONCLUSIVE,
            confidence=ConfidenceLevel.INCONCLUSIVE,
            reason=f"Attacker request returned unexpected status code HTTP {probe_b.status_code}.",
            evidence={"attacker_status": probe_b.status_code},
            probe_results=probes
        )
