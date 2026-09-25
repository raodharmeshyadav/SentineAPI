"""
SentinelAPI - Enterprise OpenAPI Security & Authorization Engine
Production-grade DAST with Differential Quad-Baseline Triangulation.

Core Architecture:
1. Dynamic OpenAPI Spec & Parameter Role Analysis (Path, Query, Nested, Body).
2. Multi-Signal BOLA Authorization Oracle (Quad-Probe: Victim, Attacker, Anon, Control).
3. Public Endpoint Declassification & Zero False-Certainty Confidence Model.
4. Schema-Aware Request Body Generation for Mutation Methods.
5. Deep Recursive PII & Infrastructure Secret Detector.
6. Rate Limiting Concurrency Fuzzer & Security Header / CORS Gateway Auditor.
"""

import re
import json
import time
import requests
import uuid
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Any, Optional, Set, Tuple

from backend.bola_oracle import (
    AuthorizationOracle,
    IdentityProfile,
    DecisionState,
    ConfidenceLevel,
    ParameterRole,
    ResponseDiffer,
    OracleVerdict
)


class OpenAPISpecParser:
    """Dynamically parses and normalizes OpenAPI 3.x and Swagger 2.0 specifications."""

    def __init__(self, spec: Dict[str, Any]):
        self.spec = spec or {}
        self.paths = self.spec.get("paths", {})
        self.components = self.spec.get("components", {})
        self.schemas = self.components.get("schemas", {})

    def resolve_schema(self, schema_obj: Dict[str, Any]) -> Dict[str, Any]:
        """Resolves internal $ref references within OpenAPI components."""
        if not isinstance(schema_obj, dict):
            return {}
        ref = schema_obj.get("$ref")
        if ref and ref.startswith("#/components/schemas/"):
            schema_name = ref.split("/")[-1]
            return self.schemas.get(schema_name, {})
        return schema_obj

    def get_endpoints(self) -> List[Dict[str, Any]]:
        endpoints = []
        for path_template, path_item in self.paths.items():
            if not isinstance(path_item, dict):
                continue

            global_params = path_item.get("parameters", [])

            for method_name, operation in path_item.items():
                if method_name.upper() not in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
                    continue

                if not isinstance(operation, dict):
                    continue

                merged_params = list(global_params) + operation.get("parameters", [])
                
                # Extract JSON request body schema if present
                req_body = operation.get("requestBody", {})
                content = req_body.get("content", {})
                json_media = content.get("application/json", {})
                body_schema = self.resolve_schema(json_media.get("schema", {}))

                endpoints.append({
                    "path": path_template,
                    "method": method_name.upper(),
                    "operation_id": operation.get("operationId", f"{method_name}_{path_template}"),
                    "summary": operation.get("summary", ""),
                    "tags": operation.get("tags", []),
                    "parameters": merged_params,
                    "request_body_schema": body_schema,
                    "responses": operation.get("responses", {})
                })

        return endpoints

    @staticmethod
    def extract_path_variables(path_template: str) -> List[str]:
        return re.findall(r"\{([a-zA-Z0-9_]+)\}", path_template)

    def synthesize_mock_body(self, schema: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Generates schema-compliant, safe minimal test payloads for write operations."""
        if not schema or not isinstance(schema, dict):
            return None

        schema = self.resolve_schema(schema)
        schema_type = schema.get("type", "object")

        if schema_type != "object":
            return None

        props = schema.get("properties", {})
        required = set(schema.get("required", []))
        payload: Dict[str, Any] = {}

        for prop_name, prop_spec in props.items():
            if not isinstance(prop_spec, dict):
                continue

            prop_spec = self.resolve_schema(prop_spec)
            p_type = prop_spec.get("type", "string")
            p_example = prop_spec.get("example")
            p_default = prop_spec.get("default")
            p_enum = prop_spec.get("enum")

            if p_example is not None:
                payload[prop_name] = p_example
            elif p_default is not None:
                payload[prop_name] = p_default
            elif p_enum:
                payload[prop_name] = p_enum[0]
            elif p_type == "integer" or p_type == "number":
                payload[prop_name] = 100
            elif p_type == "boolean":
                payload[prop_name] = True
            elif p_type == "array":
                payload[prop_name] = []
            elif p_type == "string":
                fmt = prop_spec.get("format", "")
                if fmt == "email":
                    payload[prop_name] = "test.probe@example.com"
                elif fmt == "uuid":
                    payload[prop_name] = str(uuid.uuid4())
                elif fmt == "date":
                    payload[prop_name] = "2026-09-24"
                else:
                    payload[prop_name] = f"probe_{prop_name}"
            elif p_type == "object":
                payload[prop_name] = {}

        return payload if payload else None


class SensitiveDataDetector:
    """Deep inspection engine detecting PII, credentials, and infrastructure secrets in JSON payloads."""

    SENSITIVE_KEY_PATTERNS = [
        re.compile(r"pass(word|wd)?(_hash)?", re.IGNORECASE),
        re.compile(r"secret(_key)?", re.IGNORECASE),
        re.compile(r"api[_-]?key", re.IGNORECASE),
        re.compile(r"auth[_-]?secret", re.IGNORECASE),
        re.compile(r"ssn|social[_-]?security", re.IGNORECASE),
        re.compile(r"private[_-]?key", re.IGNORECASE),
        re.compile(r"backup[_-]?codes?", re.IGNORECASE),
        re.compile(r"salary|credit[_-]?card", re.IGNORECASE)
    ]

    REGEX_VALUE_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
        (re.compile(r"\$2[aby]\$\d{2}\$[./0-9A-Za-z]{20,60}"), "Bcrypt Password Hash", "CRITICAL"),
        (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "Social Security Number (SSN)", "HIGH"),
        (re.compile(r"sk_live_[a-zA-Z0-9_]{16,}"), "Live Production API Secret Key", "CRITICAL"),
        (re.compile(r"postgres(?:ql)?:\/\/[^:]+:[^@]+@[^\/]+\/\w+"), "PostgreSQL Database Connection URI with Credentials", "CRITICAL"),
        (re.compile(r"redis:\/\/:[^@]+@[\w\.-]+:\d+"), "Redis Connection URI with Password", "CRITICAL"),
        (re.compile(r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"), "Hardcoded JWT Token", "MEDIUM"),
        (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID", "CRITICAL")
    ]

    @classmethod
    def scan_payload(cls, data: Any, current_path: str = "") -> List[Dict[str, Any]]:
        findings = []

        if isinstance(data, dict):
            for k, v in data.items():
                field_path = f"{current_path}.{k}" if current_path else k

                # Key name heuristic
                for key_pat in cls.SENSITIVE_KEY_PATTERNS:
                    if key_pat.search(k):
                        val_preview = str(v)[:40] if v is not None else "null"
                        findings.append({
                            "type": "SENSITIVE_KEY_NAME",
                            "field": field_path,
                            "label": f"Sensitive key '{k}' exposed in response",
                            "severity": "HIGH",
                            "preview": val_preview
                        })
                        break

                # Value inspection
                findings.extend(cls.scan_payload(v, field_path))

        elif isinstance(data, list):
            for idx, item in enumerate(data):
                findings.extend(cls.scan_payload(item, f"{current_path}[{idx}]"))

        elif isinstance(data, str):
            for val_pat, label, severity in cls.REGEX_VALUE_PATTERNS:
                if val_pat.search(data):
                    findings.append({
                        "type": "SECRET_PATTERN_MATCH",
                        "field": current_path,
                        "label": label,
                        "severity": severity,
                        "preview": data[:45] + ("..." if len(data) > 45 else "")
                    })

        return findings


class APISecurityAuditor:
    """
    Main Security Audit Engine.
    Executes automated authorization boundary verification, data leakage tests, and privilege validation.
    """

    def __init__(
        self,
        target_base_url: str,
        openapi_spec: Dict[str, Any],
        test_auth: Optional[Dict[str, Any]] = None,
        timeout: float = 3.5
    ):
        self.base_url = target_base_url.rstrip("/")
        self._validate_target_url(self.base_url)

        self.parser = OpenAPISpecParser(openapi_spec)
        self.timeout = timeout
        self.findings: List[Dict[str, Any]] = []
        self.logs: List[str] = []
        self.endpoints_tested = 0
        self.session = requests.Session()
        self.oracle = AuthorizationOracle(timeout=self.timeout, session=self.session)

        # Configure structured Identity Profiles
        self.tenant_a, self.tenant_b = self._init_identity_profiles(test_auth)

    @staticmethod
    def _validate_target_url(url: str):
        """SSRF & Input Safety Guard: Prevents arbitrary scheme abuse."""
        parsed = urlparse(url)
        if parsed.scheme not in ["http", "https"]:
            raise ValueError(f"Insecure or invalid URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted.")
        if not parsed.netloc:
            raise ValueError("Invalid target URL netloc.")

    def _init_identity_profiles(self, custom_auth: Optional[Dict[str, Any]]) -> Tuple[IdentityProfile, IdentityProfile]:
        """Initializes Tenant A and Tenant B identity profiles."""
        if custom_auth and "tenant_a" in custom_auth and "tenant_b" in custom_auth:
            ta = custom_auth["tenant_a"]
            tb = custom_auth["tenant_b"]
            tenant_a = IdentityProfile(
                name=ta.get("name", "Alice"),
                token=ta.get("token", "tok_alice_9981a"),
                header=ta.get("header", f"Bearer {ta.get('token', 'tok_alice_9981a')}"),
                user_id=str(ta.get("user_id", "101")),
                tenant_id=str(ta.get("tenant_id", "tenant_a")),
                label=ta.get("label", "Tenant A (Alice - Authorized User)"),
                known_objects=ta.get("known_objects", {
                    "patient_id": "101", "user_id": "101", "id": "101", "order_id": "5001", "workspace_id": "ws-101"
                })
            )
            tenant_b = IdentityProfile(
                name=tb.get("name", "Bob"),
                token=tb.get("token", "tok_bob_3342b"),
                header=tb.get("header", f"Bearer {tb.get('token', 'tok_bob_3342b')}"),
                user_id=str(tb.get("user_id", "102")),
                tenant_id=str(tb.get("tenant_id", "tenant_b")),
                label=tb.get("label", "Tenant B (Bob - Target Victim User)"),
                known_objects=tb.get("known_objects", {
                    "patient_id": "102", "user_id": "102", "id": "102", "order_id": "5002", "workspace_id": "ws-102"
                })
            )
        else:
            tenant_a = IdentityProfile(
                name="Alice",
                token="tok_alice_9981a",
                header="Bearer tok_alice_9981a",
                user_id="101",
                tenant_id="tenant_a",
                label="Tenant A (Alice - Authorized User)",
                known_objects={
                    "patient_id": "101", "user_id": "101", "id": "101", "order_id": "5001",
                    "workspace_id": "ws-101", "account_id": "101"
                },
                identity_anchors={"101", "alice", "alice_walker", "alice.w@example.com", "5001"}
            )
            tenant_b = IdentityProfile(
                name="Bob",
                token="tok_bob_3342b",
                header="Bearer tok_bob_3342b",
                user_id="102",
                tenant_id="tenant_b",
                label="Tenant B (Bob - Target Victim User)",
                known_objects={
                    "patient_id": "102", "user_id": "102", "id": "102", "order_id": "5002",
                    "workspace_id": "ws-102", "account_id": "102"
                },
                identity_anchors={"102", "bob", "bob_miller", "bob.m@example.com", "5002", "581-22-3491"}
            )

        return tenant_a, tenant_b

    def log(self, message: str):
        timestamp = time.strftime("%H:%M:%S")
        self.logs.append(f"[{timestamp}] {message}")

    def run_audit(self) -> Dict[str, Any]:
        start_time = time.time()
        self.log(f"Initializing SentinelAPI Differential Authorization Engine on {self.base_url}")

        endpoints = self.parser.get_endpoints()
        self.log(f"Discovered {len(endpoints)} route operations in OpenAPI schema.")

        # Stage 1: Security Headers & CORS Configuration
        self._audit_defensive_headers(endpoints)

        # Stage 2: Audit each discovered endpoint dynamically
        for ep in endpoints:
            self.endpoints_tested += 1
            path = ep["path"]
            method = ep["method"]
            params = ep["parameters"]
            path_vars = self.parser.extract_path_variables(path)
            query_params = [p for p in params if isinstance(p, dict) and p.get("in") == "query"]

            self.log(f"Inspecting [{method}] {path}")

            # Check A: Broken Object Level Authorization (BOLA/IDOR) on parameterized paths or queries
            is_parameterized = bool(path_vars) or any(
                self._is_identity_parameter(p.get("name", "")) for p in query_params
            )

            if is_parameterized and method in ["GET", "PUT", "PATCH", "DELETE"]:
                self._probe_bola_authorization(ep, path_vars, query_params)

            # Check B: Excessive Data Exposure & Sensitive Secret Disclosure
            if method in ["GET", "POST"]:
                self._probe_data_exposure(ep, path_vars)

            # Check C: Broken Function Level Authorization (BFLA) on administrative endpoints
            if self._is_administrative_endpoint(ep):
                self._probe_bfla_privilege_escalation(ep, path_vars)

            # Check D: Rate Limiting & Resource Consumption Fuzzing
            if self._is_high_value_endpoint(ep):
                self._probe_rate_limiting(ep)

        duration = round(time.time() - start_time, 2)
        self.log(f"Audit completed in {duration}s. Identified {len(self.findings)} findings.")

        return self._build_audit_report(duration)

    @staticmethod
    def _is_identity_parameter(name: str) -> bool:
        """Determines if a parameter name indicates an identity or object ownership identifier."""
        name_lower = name.lower().replace("-", "_")
        indicators = ["id", "uuid", "user", "patient", "account", "order", "customer", "member", "profile"]
        return any(ind in name_lower for ind in indicators)

    # ==================== HEURISTIC PROBES ====================

    def _probe_bola_authorization(
        self,
        ep: Dict[str, Any],
        path_vars: List[str],
        query_params: List[Dict[str, Any]]
    ):
        """
        Executes Quad-Probe Triangulation (Victim, Attacker, Anonymous, Control)
        via the standalone AuthorizationOracle to deterministically prove BOLA.
        """
        path = ep["path"]
        method = ep["method"]
        params = ep["parameters"]

        # Step 1: Resolve target paths & queries for Tenant B (victim) and Tenant A (control)
        victim_path, victim_query = self._resolve_parameter_targets(path, params, target_tenant=self.tenant_b)
        control_path, control_query = self._resolve_parameter_targets(path, params, target_tenant=self.tenant_a)

        victim_url = f"{self.base_url}{victim_path}"
        control_url = f"{self.base_url}{control_path}"

        # Step 2: Synthesize safe request body for write operations if required by schema
        req_body = None
        if method in ["POST", "PUT", "PATCH"]:
            req_body = self.parser.synthesize_mock_body(ep.get("request_body_schema", {}))

        # Step 3: Execute Quad-Probe Triangulation
        verdict: OracleVerdict = self.oracle.evaluate_authorization_boundary(
            method=method,
            victim_target_url=victim_url,
            control_target_url=control_url,
            tenant_a=self.tenant_a,
            tenant_b=self.tenant_b,
            victim_query_params=victim_query if victim_query else None,
            control_query_params=control_query if control_query else None,
            request_body=req_body
        )

        # Step 4: Act on Decision State
        if verdict.state == DecisionState.VULNERABLE:
            self.log(f"[!] CRITICAL BOLA Verified on {method} {path} ({verdict.confidence.value} Confidence)")
            self.findings.append({
                "id": f"VULN-BOLA-{len(self.findings) + 1}",
                "title": f"Broken Object-Level Authorization (BOLA/IDOR) on {path}",
                "category": "OWASP API1: Broken Object Level Authorization",
                "severity": "CRITICAL",
                "cvss_score": 9.4,
                "confidence": verdict.confidence.value,
                "endpoint": path,
                "method": method,
                "description": verdict.reason,
                "evidence": {
                    "target_url": victim_url,
                    "control_url": control_url,
                    "impersonated_tenant": self.tenant_a.label,
                    "target_tenant": self.tenant_b.label,
                    "decision_state": verdict.state.value,
                    "oracle_evidence": verdict.evidence
                },
                "reproduction_curl": f"curl -X {method} '{victim_url}' \\\n  -H 'Authorization: {self.tenant_a.header}'",
                "remediation_code": self._generate_bola_remediation_code(path, path_vars)
            })

        elif verdict.state == DecisionState.SECURE:
            self.log(f"[✓] Zero-Trust Enforced: {method} {path} - {verdict.reason}")

        elif verdict.state == DecisionState.PUBLIC_OR_SHARED:
            self.log(f"[i] Public/Shared Resource: {method} {path} declassified (anonymous matches victim payload).")

        elif verdict.state == DecisionState.BASELINE_INVALID:
            self.log(f"[-] Baseline Invalid on {method} {path}: Object does not exist or target rejected legitimate owner.")

        elif verdict.state == DecisionState.INCONCLUSIVE:
            self.log(f"[?] Inconclusive authorization boundary on {method} {path}: {verdict.reason}")

    def _resolve_parameter_targets(
        self,
        path: str,
        params: List[Dict[str, Any]],
        target_tenant: IdentityProfile
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Dynamically resolves path and query parameters by inspecting schemas,
        known object pools, and parameter roles without hardcoding '102'.
        """
        resolved_path = path
        resolved_query: Dict[str, Any] = {}

        for p in params:
            if not isinstance(p, dict):
                continue

            p_name = p.get("name", "")
            p_in = p.get("in", "path")
            p_schema = self.parser.resolve_schema(p.get("schema", {}))
            p_type = p_schema.get("type", "string")
            p_format = p_schema.get("format", "")

            # 1. Determine target candidate value for this parameter and tenant
            candidate_val = None

            # Check known object pool for tenant
            clean_name = p_name.lower().replace("-", "_")
            if clean_name in target_tenant.known_objects:
                candidate_val = target_tenant.known_objects[clean_name]
            elif any(k in clean_name for k in ["patient", "user", "account", "member", "customer"]):
                candidate_val = target_tenant.user_id
            elif "order" in clean_name and "order_id" in target_tenant.known_objects:
                candidate_val = target_tenant.known_objects["order_id"]
            elif "workspace" in clean_name and "workspace_id" in target_tenant.known_objects:
                candidate_val = target_tenant.known_objects["workspace_id"]
            elif p_format == "uuid":
                # Deterministic or valid UUID
                candidate_val = f"00000000-0000-0000-0000-{int(target_tenant.user_id):012d}" if target_tenant.user_id.isdigit() else str(uuid.uuid4())
            elif p.get("example") is not None:
                candidate_val = str(p.get("example"))
            elif p_schema.get("example") is not None:
                candidate_val = str(p_schema.get("example"))
            elif p_schema.get("enum"):
                candidate_val = str(p_schema.get("enum")[0])
            elif p_type == "integer":
                candidate_val = target_tenant.user_id if target_tenant.user_id.isdigit() else "1"
            else:
                candidate_val = target_tenant.user_id

            # 2. Inject into path or query
            if p_in == "path":
                p_token = f"{{{p_name}}}"
                resolved_path = resolved_path.replace(p_token, str(candidate_val))
            elif p_in == "query":
                resolved_query[p_name] = candidate_val

        # Catch unresolved generic tokens in path
        resolved_path = re.sub(r"\{[a-zA-Z0-9_]+\}", target_tenant.user_id, resolved_path)
        return resolved_path, resolved_query

    def _probe_data_exposure(self, ep: Dict[str, Any], path_vars: List[str]):
        """Probes endpoints for unfiltered database columns, credentials, or PII."""
        path = ep["path"]
        method = ep["method"]
        resolved_path, query_params = self._resolve_parameter_targets(path, ep["parameters"], target_tenant=self.tenant_a)
        target_url = f"{self.base_url}{resolved_path}"
        headers = {"Authorization": self.tenant_a.header, "Accept": "application/json"}

        try:
            res = self.session.request(method, target_url, headers=headers, params=query_params if query_params else None, timeout=self.timeout)
            if res.status_code == 200:
                payload = self._safe_json(res)
                if payload:
                    exposed_items = SensitiveDataDetector.scan_payload(payload)
                    if exposed_items:
                        highest_sev = "HIGH"
                        if any(item.get("severity") == "CRITICAL" for item in exposed_items):
                            highest_sev = "CRITICAL"

                        self.log(f"[!] {highest_sev}: Excessive data exposure on {method} {path}")
                        self.findings.append({
                            "id": f"VULN-DATA-{len(self.findings) + 1}",
                            "title": f"Excessive Data Exposure & Secret Leakage on {path}",
                            "category": "OWASP API3: Broken Object Property Level Authorization",
                            "severity": highest_sev,
                            "cvss_score": 8.6 if highest_sev == "CRITICAL" else 7.5,
                            "endpoint": path,
                            "method": method,
                            "description": (
                                f"Response payload serializes internal database columns and confidential properties. "
                                f"Detected {len(exposed_items)} high-entropy secrets or sensitive field names in response."
                            ),
                            "evidence": {
                                "target_url": target_url,
                                "leaks_detected": [f"{item['label']} ({item.get('preview', '')})" for item in exposed_items[:4]],
                                "sample_payload": self._truncate_payload(payload)
                            },
                            "reproduction_curl": f"curl -X {method} '{target_url}' \\\n  -H 'Authorization: {self.tenant_a.header}'",
                            "remediation_code": self._generate_dto_remediation_code(path)
                        })
        except Exception as e:
            self.log(f"Data exposure probe error on {path}: {e}")

    def _probe_bfla_privilege_escalation(self, ep: Dict[str, Any], path_vars: List[str]):
        """Verifies if unprivileged user tokens can execute administrative operations."""
        path = ep["path"]
        method = ep["method"]
        resolved_path, query_params = self._resolve_parameter_targets(path, ep["parameters"], target_tenant=self.tenant_b)
        target_url = f"{self.base_url}{resolved_path}"
        headers = {"Authorization": self.tenant_a.header, "Accept": "application/json"}

        try:
            res = self.session.request(method, target_url, headers=headers, params=query_params if query_params else None, timeout=self.timeout)
            if res.status_code in [200, 201, 202, 204]:
                self.log(f"[!] CRITICAL: Function Level Privilege Escalation on {method} {path}")
                self.findings.append({
                    "id": f"VULN-BFLA-{len(self.findings) + 1}",
                    "title": f"Broken Function Level Authorization (Privilege Escalation) on {path}",
                    "category": "OWASP API5: Broken Function Level Authorization",
                    "severity": "CRITICAL",
                    "cvss_score": 9.1,
                    "endpoint": path,
                    "method": method,
                    "description": (
                        f"An administrative endpoint was successfully invoked by a standard, unprivileged client token. "
                        f"The server failed to enforce role-based access control (RBAC) boundaries."
                    ),
                    "evidence": {
                        "target_url": target_url,
                        "used_credentials": self.tenant_a.label,
                        "http_status": res.status_code,
                        "response_excerpt": str(res.text)[:180]
                    },
                    "reproduction_curl": f"curl -X {method} '{target_url}' \\\n  -H 'Authorization: {self.tenant_a.header}'",
                    "remediation_code": self._generate_rbac_remediation_code(path, method)
                })
        except Exception as e:
            self.log(f"BFLA probe error on {path}: {e}")

    def _probe_rate_limiting(self, ep: Dict[str, Any]):
        """Executes concurrent burst requests to verify request throttling and rate limiting."""
        path = ep["path"]
        method = ep["method"]
        target_url = f"{self.base_url}{path}"
        burst_size = 15

        def _send_req(_):
            try:
                if method == "POST":
                    r = requests.post(target_url, json={"username": "probe_user", "password": "wrong_password_test"}, timeout=2.0)
                else:
                    r = requests.get(target_url, headers={"Authorization": self.tenant_a.header}, timeout=2.0)
                return r.status_code
            except Exception:
                return 0

        try:
            with ThreadPoolExecutor(max_workers=5) as executor:
                results = list(executor.map(_send_req, range(burst_size)))

            if 429 in results:
                self.log(f"[✓] Rate Limiting Active: {path} throttled with HTTP 429.")
                return

            accepted_count = sum(1 for code in results if code in [200, 400, 401, 404, 422])
            if accepted_count >= burst_size - 2:
                self.log(f"[!] MEDIUM: Missing rate limiting on {path}")
                self.findings.append({
                    "id": f"VULN-RATE-{len(self.findings) + 1}",
                    "title": f"Unrestricted Resource Consumption / Missing Rate Limiting on {path}",
                    "category": "OWASP API4: Unrestricted Resource Consumption",
                    "severity": "MEDIUM",
                    "cvss_score": 5.9,
                    "endpoint": path,
                    "method": method,
                    "description": (
                        f"The endpoint accepted {accepted_count} consecutive requests within a concurrent burst "
                        f"without throttling (HTTP 429). This enables credential brute-forcing and resource exhaustion."
                    ),
                    "evidence": {
                        "burst_requests_sent": burst_size,
                        "unthrottled_responses": accepted_count
                    },
                    "reproduction_curl": f"for i in {{1..{burst_size}}}; do curl -s -o /dev/null -w '%{{http_code}}\\n' {target_url}; done",
                    "remediation_code": self._generate_ratelimit_remediation_code(path)
                })
        except Exception:
            pass

    def _audit_defensive_headers(self, endpoints: List[Dict[str, Any]]):
        """Audits reverse proxy and application defensive headers against health or root endpoint."""
        health_path = "/api/v1/health"
        # Find any non-parameterized GET endpoint from spec if health is absent
        available_paths = [ep["path"] for ep in endpoints if ep["method"] == "GET" and "{" not in ep["path"]]
        test_path = health_path if health_path in available_paths or not available_paths else available_paths[0]

        try:
            r = self.session.get(f"{self.base_url}{test_path}", timeout=3.0)
            headers = r.headers
            missing = []

            required = [
                ("Strict-Transport-Security", "Enforces HTTPS encryption"),
                ("X-Content-Type-Options", "Prevents MIME-sniffing"),
                ("X-Frame-Options", "Prevents UI clickjacking"),
                ("Content-Security-Policy", "Restricts unauthorized script execution")
            ]

            for header_name, desc in required:
                if header_name not in headers:
                    missing.append(f"{header_name} ({desc})")

            if missing:
                self.findings.append({
                    "id": f"VULN-HDR-{len(self.findings) + 1}",
                    "title": "Missing Standard Defensive HTTP Security Headers",
                    "category": "OWASP API8: Security Misconfiguration",
                    "severity": "MEDIUM",
                    "cvss_score": 5.3,
                    "endpoint": test_path,
                    "method": "GET",
                    "description": "Server responses omit essential defensive HTTP headers recommended by OWASP.",
                    "evidence": {"missing_headers": missing},
                    "reproduction_curl": f"curl -I {self.base_url}{test_path}",
                    "remediation_code": """# Middleware patch in FastAPI
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response"""
                })

            # Check CORS
            if headers.get("Access-Control-Allow-Origin") == "*":
                self.findings.append({
                    "id": f"VULN-CORS-{len(self.findings) + 1}",
                    "title": "Permissive Wildcard Access-Control-Allow-Origin (*)",
                    "category": "OWASP API8: Security Misconfiguration",
                    "severity": "MEDIUM",
                    "cvss_score": 6.5,
                    "endpoint": test_path,
                    "method": "GET",
                    "description": "CORS header is configured with wildcard '*', allowing arbitrary third-party domains to access sensitive endpoints.",
                    "evidence": {"observed_header": "Access-Control-Allow-Origin: *"},
                    "reproduction_curl": f"curl -H 'Origin: https://malicious-site.com' -I {self.base_url}{test_path}",
                    "remediation_code": """# Restrict CORS to explicit trusted origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://trusted-domain.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)"""
                })
        except Exception:
            pass

    @staticmethod
    def _is_administrative_endpoint(ep: Dict[str, Any]) -> bool:
        path = ep["path"].lower()
        method = ep["method"]
        tags = [t.lower() for t in ep.get("tags", [])]
        return (
            "admin" in path
            or "admin" in tags
            or method == "DELETE"
            or "manage" in path
            or ("users/{id}" in path and method in ["DELETE", "PUT"])
        )

    @staticmethod
    def _is_high_value_endpoint(ep: Dict[str, Any]) -> bool:
        path = ep["path"].lower()
        return any(k in path for k in ["login", "auth", "token", "export", "download"])

    @staticmethod
    def _safe_json(res: requests.Response) -> Any:
        try:
            return res.json()
        except Exception:
            return None

    @staticmethod
    def _truncate_payload(data: Any, max_len: int = 250) -> Any:
        if isinstance(data, dict):
            preview = {}
            for k, v in list(data.items())[:5]:
                preview[k] = str(v)[:40] if v is not None else None
            return preview
        return str(data)[:max_len]

    # ==================== REMEDIATION TEMPLATES ====================

    @staticmethod
    def _generate_bola_remediation_code(path: str, path_vars: List[str]) -> str:
        var_name = path_vars[0] if path_vars else "resource_id"
        return f"""# Zero-Trust Ownership Validation
from fastapi import HTTPException, Depends, status

@app.get("{path}")
def get_resource({var_name}: str, current_user = Depends(get_current_user)):
    # 1. Enforce tenant isolation check
    if current_user.role != "admin" and current_user.id != {var_name}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied: You do not own this resource."
        )
    return db.query_resource({var_name})"""

    @staticmethod
    def _generate_dto_remediation_code(path: str) -> str:
        return f"""# Data Transfer Object (DTO) Filtering
from pydantic import BaseModel, EmailStr

class SafePublicResponse(BaseModel):
    id: str
    username: str
    # Sensitive database columns (password_hash, ssn) excluded
    
    class Config:
        from_attributes = True

@app.get("{path}", response_model=SafePublicResponse)
def get_data(current_user = Depends(get_current_user)):
    return db.get_user(current_user.id)"""

    @staticmethod
    def _generate_rbac_remediation_code(path: str, method: str) -> str:
        return f"""# Role-Based Access Control (RBAC) Dependency
def require_admin_role(current_user = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Administrative privileges required.")
    return current_user

@app.{method.lower()}("{path}", dependencies=[Depends(require_admin_role)])
def administrative_handler():
    return {{"status": "action_executed"}}"""

    @staticmethod
    def _generate_ratelimit_remediation_code(path: str) -> str:
        return f"""# Rate Limiting Guard
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.api_route("{path}")
@limiter.limit("5/minute")
def throttled_endpoint(request: Request):
    return process_request()"""

    # ==================== SCORING & SUMMARY ====================

    def _build_audit_report(self, duration: float) -> Dict[str, Any]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            sev = f.get("severity", "LOW")
            counts[sev] = counts.get(sev, 0) + 1

        penalty = (counts["CRITICAL"] * 25) + (counts["HIGH"] * 15) + (counts["MEDIUM"] * 8) + (counts["LOW"] * 3)
        score = max(5, 100 - penalty)
        grade = "A+" if score >= 95 else ("A" if score >= 85 else ("B" if score >= 75 else ("C" if score >= 60 else "F")))

        summary = {
            "score": score,
            "grade": grade,
            "counts": counts,
            "total_findings": len(self.findings),
            "endpoints_tested": self.endpoints_tested,
            "duration_seconds": duration
        }

        return {
            "summary": summary,
            "score": score,
            "grade": grade,
            "critical_count": counts["CRITICAL"],
            "high_count": counts["HIGH"],
            "endpoints_scanned": self.endpoints_tested,
            "duration_seconds": duration,
            "scan_id": f"AUDIT-{int(time.time())}",
            "findings": self.findings,
            "logs": self.logs,
            "target_url": self.base_url,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
