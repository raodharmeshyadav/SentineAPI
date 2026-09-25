"""
Apex Health & Pay - Intentionally Vulnerable Target Sandbox API
Demonstrates classic OWASP API Security Top 10 (2023) vulnerabilities:
- API1: BOLA / IDOR (Broken Object Level Authorization)
- API2: Broken Authentication & Token Handling
- API3: Broken Object Property Level Authorization / Excessive Data Exposure
- API4: Unrestricted Resource Consumption (Missing Rate Limiting)
- API5: Broken Function Level Authorization (BFLA)
- API8: Security Misconfiguration (Missing Security Headers, Permissive CORS)
"""

from fastapi import FastAPI, Header, HTTPException, status, Query, Path
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import time

app = FastAPI(
    title="Apex Health & Pay API",
    description="Production-grade mock API for zero-trust vulnerability assessment & developer security auditing.",
    version="2.4.0",
    docs_url="/docs",
    openapi_url="/openapi.json"
)

# Vulnerability API8: Overly permissive CORS with wildcard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mock In-Memory Database
USERS_DB = {
    "alice": {
        "id": "101",
        "username": "alice_walker",
        "email": "alice.w@example.com",
        "full_name": "Dr. Alice Walker",
        "token": "tok_alice_9981a",
        "role": "user",
        # Sensitive data leaked via Excessive Data Exposure
        "password_hash": "$2b$12$e8yO/3d2XG4XjQ7M0RzIue1bH29vKzLopQ9.g3nUv7xWp",
        "ssn": "452-88-9102",
        "internal_auth_secret": "sk_live_sec_991823_prod_ak",
        "salary_tier": "$145,000",
        "is_superadmin": False,
        "mfa_backup_codes": ["7712-9901", "8831-2290"]
    },
    "bob": {
        "id": "102",
        "username": "bob_miller",
        "email": "bob.m@example.com",
        "full_name": "Bob Miller",
        "token": "tok_bob_3342b",
        "role": "user",
        # Sensitive data leaked via Excessive Data Exposure
        "password_hash": "$2b$12$K19z8Fq0Lp3Mm8Vx0Yv.Uu7hRt6yEq1WvBn3mK2lOp8sX",
        "ssn": "581-22-3491",
        "internal_auth_secret": "sk_live_sec_109284_prod_bm",
        "salary_tier": "$98,000",
        "is_superadmin": False,
        "mfa_backup_codes": ["1129-4402", "5591-8823"]
    },
    "charlie": {
        "id": "999",
        "username": "admin_charlie",
        "email": "charlie.admin@apexhealth.internal",
        "full_name": "Charlie Admin",
        "token": "tok_admin_7711c",
        "role": "admin",
        "password_hash": "$2b$12$Adm1nSecur3H4shK99vQ11mP88xx0LpQrt91U",
        "ssn": "900-11-0001",
        "internal_auth_secret": "sk_live_root_superkey_master_771",
        "salary_tier": "$210,000",
        "is_superadmin": True,
        "mfa_backup_codes": ["0001-9999", "1234-5678"]
    }
}

PATIENT_RECORDS = {
    "101": {
        "patient_id": "101",
        "patient_name": "Alice Walker",
        "age": 34,
        "blood_group": "A+",
        "primary_physician": "Dr. Sarah Adams",
        "clinical_diagnosis": "Mild Hypertension, Seasonal Rhinitis",
        "prescriptions": ["Lisinopril 10mg", "Cetirizine 10mg"],
        "lab_reports": [
            {"date": "2026-08-14", "test": "Lipid Profile", "status": "Normal"},
            {"date": "2026-09-02", "test": "Complete Blood Count", "status": "Stable"}
        ],
        "insurance_policy_number": "INSR-ALICE-991823-TX",
        "emergency_contact": "+1-555-019-2831"
    },
    "102": {
        "patient_id": "102",
        "patient_name": "Bob Miller",
        "age": 42,
        "blood_group": "O-",
        "primary_physician": "Dr. Keith Vance",
        "clinical_diagnosis": "Stage 2 Chronic Kidney Disease, Type 2 Diabetes Mellitus",
        "confidential_notes": "Patient undergoing confidential psychiatric counselling for acute clinical depression.",
        "prescriptions": ["Metformin 500mg", "Sertraline 50mg", "Insulin Glargine 20u"],
        "lab_reports": [
            {"date": "2026-07-20", "test": "HbA1c", "status": "Elevated (8.4%)"},
            {"date": "2026-08-30", "test": "eGFR", "status": "Diminished (48 mL/min)"}
        ],
        "insurance_policy_number": "INSR-BOB-334211-CA",
        "emergency_contact": "+1-555-014-9981"
    }
}

ORDERS_DB = {
    "5001": {
        "order_id": "5001",
        "owner_id": "101",
        "customer": "Alice Walker",
        "amount": 249.99,
        "status": "Delivered",
        "items": ["Prescription Refill #49", "BP Digital Monitor Pro"],
        "payment_method": "Visa ending in 4242",
        "billing_address": "742 Evergreen Terrace, Austin, TX 78701"
    },
    "5002": {
        "order_id": "5002",
        "owner_id": "102",
        "customer": "Bob Miller",
        "amount": 1289.50,
        "status": "Processing",
        "items": ["Continuous Glucose Monitoring Sensor (3-Month Supply)", "Insulin Cool-Storage Bag"],
        "payment_method": "MasterCard ending in 8819",
        "billing_address": "404 Ocean Boulevard, Santa Monica, CA 90401"
    }
}

TOKEN_TO_USER = {
    "tok_alice_9981a": USERS_DB["alice"],
    "tok_bob_3342b": USERS_DB["bob"],
    "tok_admin_7711c": USERS_DB["charlie"]
}


def authenticate_token(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """Helper to validate token presence, but fails to enforce granular authorization."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization Header. Expected 'Bearer <token>'"
        )
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization scheme. Use 'Bearer <token>'"
        )
    token = parts[1]
    if token not in TOKEN_TO_USER:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token."
        )
    return TOKEN_TO_USER[token]


# --- Health & Metadata ---
@app.get("/api/v1/health", tags=["System"])
def health_check():
    """System health check endpoint."""
    return {
        "status": "healthy",
        "service": "Apex Health & Pay API",
        "version": "2.4.0",
        "timestamp": time.time()
    }


# --- Authentication ---
class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/v1/auth/login", tags=["Authentication"])
def login(creds: LoginRequest):
    """
    User login endpoint.
    VULNERABILITY API4: No rate limiting implemented. Susceptible to brute force / credential stuffing.
    """
    for user in USERS_DB.values():
        if user["username"] == creds.username and creds.password in ["password123", "admin2026"]:
            return {
                "access_token": user["token"],
                "token_type": "Bearer",
                "expires_in": 86400,
                "user_id": user["id"],
                "role": user["role"]
            }
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")


# --- Patient Medical Records (VULNERABILITY: BOLA / IDOR) ---
@app.get("/api/v1/patients/{patient_id}/records", tags=["Patients"])
def get_patient_records(
    patient_id: str = Path(..., description="Target patient record ID (e.g., 101 or 102)"),
    authorization: Optional[str] = Header(None)
):
    """
    Fetch patient clinical records.
    VULNERABILITY API1:2023 (BOLA / IDOR):
    Verifies that the request has A valid token, but FAILS to verify if the token
    belongs to patient_id or an authorized caregiver!
    User Alice (101) can view Bob's confidential medical records (102).
    """
    user = authenticate_token(authorization)
    
    if patient_id not in PATIENT_RECORDS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Patient record not found")
        
    # Deliberate vulnerability: Zero object-level authorization check!
    return PATIENT_RECORDS[patient_id]


# --- Orders & Financials (VULNERABILITY: BOLA / IDOR) ---
@app.get("/api/v1/orders/{order_id}", tags=["Orders"])
def get_order_details(
    order_id: str = Path(..., description="Order ID (e.g., 5001 or 5002)"),
    authorization: Optional[str] = Header(None)
):
    """
    Retrieve order details and payment records.
    VULNERABILITY API1:2023 (BOLA / IDOR):
    Any authenticated user can inspect any customer's financial transactions.
    """
    user = authenticate_token(authorization)
    
    if order_id not in ORDERS_DB:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")
        
    return ORDERS_DB[order_id]


# --- User Profile (VULNERABILITY: Excessive Data Exposure) ---
@app.get("/api/v1/users/{user_id}/profile", tags=["Users"])
def get_user_profile(
    user_id: str = Path(..., description="User ID"),
    authorization: Optional[str] = Header(None)
):
    """
    Retrieve user public profile.
    VULNERABILITY API3:2023 (Excessive Data Exposure):
    Directly returns internal database record dictionary containing sensitive attributes:
    password_hash, ssn, internal_auth_secret, salary_tier, mfa_backup_codes!
    """
    user = authenticate_token(authorization)
    
    target_user = None
    for u in USERS_DB.values():
        if u["id"] == user_id:
            target_user = u
            break
            
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        
    # Leaks full internal user dictionary without a strict response model/DTO
    return target_user


# --- Admin Endpoint (VULNERABILITY: Broken Function Level Authorization - BFLA) ---
@app.delete("/api/v1/admin/users/{user_id}", tags=["Admin"])
def delete_user_by_admin(
    user_id: str = Path(..., description="Target user ID to delete"),
    authorization: Optional[str] = Header(None)
):
    """
    Administrative endpoint to purge user accounts.
    VULNERABILITY API5:2023 (BFLA):
    Accepts any authenticated standard user token without verifying if user['role'] == 'admin'!
    """
    user = authenticate_token(authorization)
    
    # Deliberate vulnerability: missing `if user["role"] != "admin": raise 403`
    return {
        "status": "success",
        "message": f"User ID {user_id} deleted successfully by admin action.",
        "executed_by_token_holder": user["username"]
    }


# --- System Debug (VULNERABILITY: Information Disclosure) ---
@app.get("/api/v1/system/debug-logs", tags=["System"])
def get_debug_logs(
    authorization: Optional[str] = Header(None)
):
    """
    System telemetry and diagnostics.
    VULNERABILITY API8: Information Leakage of internal infrastructure credentials.
    """
    authenticate_token(authorization)
    return {
        "environment": "production-us-east-1",
        "database_uri": "postgres://apex_admin:P@ssw0rd9912!@db-internal.apexhealth.net:5432/core_records",
        "redis_cache": "redis://:ApeX_R3d1s_K3y@10.0.4.12:6379/0",
        "aws_s3_bucket": "s3://apex-confidential-medical-backups-2026/",
        "active_worker_threads": 16,
        "debug_mode": True
    }


# --- Report Export (VULNERABILITY: Missing Rate Limiting / DoS Risk) ---
@app.get("/api/v1/reports/export", tags=["Reports"])
def export_large_dataset(
    range_days: int = Query(30, description="Report range in days"),
    authorization: Optional[str] = Header(None)
):
    """
    Heavy query endpoint that generates audit archives.
    VULNERABILITY API4: No rate limiting, unbounded resource consumption.
    """
    authenticate_token(authorization)
    # Simulates expensive generation
    return {
        "status": "generated",
        "rows_processed": 145000,
        "export_url": "https://cdn.apexhealth.net/exports/audit_report_20260924.csv",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }


# =====================================================================
# BENCHMARK FIXTURE SUITE (Phase 16 Reference Implementations)
# =====================================================================

# 1. Public Doctor Resource (Public / Shared Baseline - NOT BOLA)
DOCTORS_DB = {
    "doc_1": {"doctor_id": "doc_1", "name": "Dr. Sarah Adams", "specialty": "Cardiology", "clinic": "Apex Central"},
    "doc_2": {"doctor_id": "doc_2", "name": "Dr. Keith Vance", "specialty": "Nephrology", "clinic": "Apex West"}
}

@app.get("/api/v1/doctors/{doctor_id}", tags=["Benchmark - Public"])
def get_public_doctor(doctor_id: str = Path(..., description="Doctor ID")):
    """Public catalog endpoint. Shared representation across all identities."""
    if doctor_id not in DOCTORS_DB:
        raise HTTPException(status_code=404, detail="Doctor not found")
    return DOCTORS_DB[doctor_id]


# 2. Query Parameter BOLA (OWASP API1 via Query String)
@app.get("/api/v1/patient-query", tags=["Benchmark - Query Parameter"])
def query_patient_records(
    patient_id: str = Query(..., description="Target patient ID"),
    authorization: Optional[str] = Header(None)
):
    """BOLA via Query Parameter (?patient_id=102). Fails object authorization."""
    authenticate_token(authorization)
    if patient_id not in PATIENT_RECORDS:
        raise HTTPException(status_code=404, detail="Patient record not found")
    return PATIENT_RECORDS[patient_id]


# 3. UUID-based Resource (Non-integer resource identifiers)
WORKSPACES_DB = {
    "00000000-0000-0000-0000-000000000101": {
        "workspace_id": "00000000-0000-0000-0000-000000000101",
        "owner_id": "101",
        "name": "Alice Research Workspace",
        "files_count": 42
    },
    "00000000-0000-0000-0000-000000000102": {
        "workspace_id": "00000000-0000-0000-0000-000000000102",
        "owner_id": "102",
        "name": "Bob Clinical Workspace",
        "files_count": 89
    }
}

@app.get("/api/v1/workspaces/{workspace_id}", tags=["Benchmark - UUID"])
def get_workspace(
    workspace_id: str = Path(..., description="Target Workspace UUID"),
    authorization: Optional[str] = Header(None)
):
    """UUID BOLA vulnerability. Cross-tenant workspace retrieval without ownership check."""
    authenticate_token(authorization)
    if workspace_id not in WORKSPACES_DB:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return WORKSPACES_DB[workspace_id]


# 4. Nested Resource (Parent Scope vs Object Identifier)
STAFF_DB = {
    "cardio": {
        "staff_101": {"staff_id": "staff_101", "dept_id": "cardio", "user_id": "101", "role": "Fellow"},
        "staff_102": {"staff_id": "staff_102", "dept_id": "cardio", "user_id": "102", "role": "Senior Consultant"}
    }
}

@app.get("/api/v1/departments/{dept_id}/staff/{staff_id}", tags=["Benchmark - Nested"])
def get_department_staff(
    dept_id: str = Path(..., description="Department Scope"),
    staff_id: str = Path(..., description="Staff Member ID"),
    authorization: Optional[str] = Header(None)
):
    """Nested route BOLA. Scope verification gap."""
    authenticate_token(authorization)
    dept = STAFF_DB.get(dept_id)
    if not dept or staff_id not in dept:
        raise HTTPException(status_code=404, detail="Staff record not found in department")
    return dept[staff_id]


# 5. POST/PUT Mutation BOLA with Request Body
class PatientVitalsUpdate(BaseModel):
    heart_rate: int = 75
    systolic_bp: int = 120
    diastolic_bp: int = 80
    notes: Optional[str] = "Routine examination"

@app.post("/api/v1/patients/{patient_id}/vitals", tags=["Benchmark - Mutation Write"])
def update_patient_vitals(
    patient_id: str = Path(..., description="Target Patient ID"),
    vitals: PatientVitalsUpdate = ...,
    authorization: Optional[str] = Header(None)
):
    """Write-operation BOLA (Unauthorized mutation of another tenant's medical telemetry)."""
    user = authenticate_token(authorization)
    if patient_id not in PATIENT_RECORDS:
        raise HTTPException(status_code=404, detail="Patient not found")
    
    return {
        "status": "updated",
        "patient_id": patient_id,
        "recorded_by": user["username"],
        "telemetry": vitals.dict(),
        "updated_at": time.time()
    }


# 6. Secure Masked 404 Endpoint (Ground truth exists, but unauthorized requests receive 404)
@app.get("/api/v1/secure/masked-records/{record_id}", tags=["Benchmark - Masked 404"])
def get_masked_record(
    record_id: str = Path(..., description="Record ID"),
    authorization: Optional[str] = Header(None)
):
    """Demonstrates secure 404 masking: Only the true owner (user_id) sees the object."""
    user = authenticate_token(authorization)
    if record_id == "rec_bob_102":
        if user["id"] == "102":
            return {"record_id": "rec_bob_102", "owner_id": "102", "confidential_data": "Bob Private Record"}
        else:
            # Intentionally return 404 to hide object existence from Tenant A
            raise HTTPException(status_code=404, detail="Record not found")
    elif record_id == "rec_alice_101":
        if user["id"] == "101":
            return {"record_id": "rec_alice_101", "owner_id": "101", "confidential_data": "Alice Private Record"}
        else:
            raise HTTPException(status_code=404, detail="Record not found")
    raise HTTPException(status_code=404, detail="Record not found")

