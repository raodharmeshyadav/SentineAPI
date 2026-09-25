# SENTINEL-API : ZERO-TRUST API VULNERABILITY SCANNER
### AMI HACKS 1.0 — Track C (Industry / Deep-Tech)
**Team Presentation Guide, Slide Deck Blueprint & 3-Minute Live Demo Pitch**

---

## 🎯 Executive Slide Deck Structure (8 Slides)

### Slide 1: Title & The Hook (15 Seconds)
- **Title**: SentinelAPI — Zero-Trust Autonomous API Vulnerability Scanner & Remediation Engine
- **Tagline**: *"Catch the API logic vulnerability before the breach headline does."*
- **Team**: [Your Team Name] | Amity School of Engineering & Technology
- **The Hook (Speaker 1)**: 
  > *"Judges, in 2026, over 80% of data breaches originate from APIs. Not because firewalls failed, but because APIs leak data by design through broken authorization logic like BOLA and IDOR. Today, we built SentinelAPI to automate zero-trust defense."*

---

### Slide 2: The Critical Industry Problem (30 Seconds)
- **The API Security Gap**:
  - Developers ship APIs daily with rapid CI/CD velocity.
  - Traditional security scanners (DAST/SAST) only look for syntax errors or missing headers.
  - **The Blind Spot**: They miss **Logic Flaws** — e.g., when User A's syntactically valid token accesses User B's patient health records or financial transactions.
- **Pain Points**:
  1. Manual penetration testing takes weeks and costs \$20,000+ per audit.
  2. Enterprise tools (Noname, Salt) are priced out of reach for startups and mid-market teams.
  3. Security reports dump raw logs without actionable remediation code.

---

### Slide 3: Our Solution: SentinelAPI Architecture (30 Seconds)
- **Zero-Trust Autonomous Audit Pipeline**:
  1. **Spec Ingestion Engine**: Ingests OpenAPI 3.0 / Swagger specs or live endpoints dynamically.
  2. **Multi-Tenant Dual-Token Matrix**: Simulates concurrent authenticated personas (Tenant Alice vs Victim Bob) to deterministically prove BOLA/IDOR with 0% false positives.
  3. **Deep Heuristic & PII Inspection**: Scans response payloads for leaked hashes, SSNs, and secret tokens (Excessive Data Exposure).
  4. **BFLA / Privilege Escalation Hunter**: Tests unprivileged tokens against administrative endpoints.
  5. **Automated AI Remediation**: Generates instant line-by-line secure code patches (FastAPI / Express).

---

### Slide 4: Real-World Demonstration — Apex Health & Pay Sandbox (60 Seconds)
*(Switch to Live Dashboard Screen: http://127.0.0.1:8000)*
- Show the **Dark Mode Cyber SOC Dashboard**.
- Click **"Run Live Audit"**:
  - Watch the live terminal logs audit 8 endpoints in **0.4 seconds**.
  - Show the Security Posture drop to **Score 5/100 (Grade F)**.
  - Unveil **10 critical/high vulnerabilities** categorized by OWASP API Security Top 10 (2023).
- Open **Vulnerability #1: BOLA on `/api/v1/patients/{patient_id}/records`**:
  - Click **[🔥 View Exploit PoC]**: Show the exact cURL and how Alice's token retrieved Bob's confidential medical diagnosis.
  - Click **[🛠️ AI Remediation Patch]**: Show the immediate object-level ownership check code patch for developers.
- Open **Vulnerability #2: Excessive Data Exposure on `/api/v1/users/{id}/profile`**:
  - Show leaked `password_hash`, `ssn`, and `internal_auth_secret`.
  - Show the recommended Pydantic DTO response model patch.

---

### Slide 5: Technical Innovation & USP (30 Seconds)
- **Why SentinelAPI Beats Generic Scanners**:
  | Feature | Traditional Scanners (OWASP ZAP) | Expensive Enterprise (Salt/Noname) | **SentinelAPI (Our Solution)** |
  | :--- | :--- | :--- | :--- |
  | **BOLA / IDOR Logic Detection** | ❌ No (Misses logic) | ✅ Yes | **✅ Automated Multi-Persona Engine** |
  | **Instant Developer Code Fix** | ❌ Only descriptions | ❌ Generic advice | **✅ Side-by-Side Code Patches** |
  | **Execution Speed** | ⏱️ 15-30 minutes | ⏱️ Cloud Queue | **⚡ Sub-Second (0.4s for 8 endpoints)** |
  | **Accessibility** | ⚠️ Complex Java GUI | 💸 \$50k/year SaaS | **🌐 Lightweight Web SOC + 1-Click HTML Report** |

---

### Slide 6: Business Model & Market Feasibility (15 Seconds)
- **Target Market**: Cloud-native startups, Fintechs, Healthcare APIs, and DevSecOps teams.
- **Delivery Models**:
  1. **Developer Open-Core CLI**: Free automated audit for individual developers.
  2. **CI/CD Security Gate (GitHub Action)**: Blocks pull requests if a commit introduces a critical BOLA vulnerability.
  3. **Enterprise Compliance Reporting**: Automated HIPAA, GDPR, and PCI-DSS audit compliance export.

---

### Slide 7: Future Roadmap (15 Seconds)
- **Phase 1 (Achieved Today)**: Full OWASP API Top 10 automated scanner, multi-tenant BOLA testing, and code patch generator.
- **Phase 2 (Next 60 Days)**: GitHub Action & GitLab CI integration with SARIF export.
- **Phase 3**: Agentic multi-step exploit chaining (e.g. pivoting from an authentication bypass into an administrative data exfiltration chain).

---

### Slide 8: Conclusion & Call to Action (10 Seconds)
- *"SentinelAPI turns every API developer into their own AppSec engineer. Don't wait for a data breach to audit your APIs."*
- **Thank you! We are open for Questions & Live Pentest Trials.**

---

## 🎤 3-Minute Word-by-Word Pitch Script

**[0:00 - 0:30] Introduction & Problem:**
> *"Good afternoon respected judges! Modern tech companies are powered by hundreds of microservice APIs. But while developers push code multiple times a day, API security reviews only happen manually once or twice a year.*
> *The result? Logic flaws like Broken Object-Level Authorization—where User A accesses User B's private data—remain undetected until a headline breach occurs.*
> *Traditional web scanners only detect syntactic bugs, missing business logic entirely. To solve this, we built **SentinelAPI**—an autonomous zero-trust vulnerability scanner and remediation platform."*

**[0:30 - 1:45] Live Demo Walkthrough:**
> *"Let us show you SentinelAPI live in action.*
> *Here on screen is our Cyber Defense SOC. We have configured it against a live test sandbox API—Apex Health & Pay.*
> *With a single click on 'Run Live Audit', SentinelAPI ingests the OpenAPI specification, maps all endpoints, and deploys our dual-persona authorization engine.*
> *In just 0.4 seconds, SentinelAPI audited 8 endpoints and flagged **10 critical vulnerabilities**.*
> *Look at this finding: **BOLA on patient medical records**. By swapping authentication tokens between Tenant Alice and Tenant Bob, SentinelAPI proved that Alice can extract Bob's confidential medical records and clinical diagnoses!*
> *Notice we don't just dump a vague error log. We provide a **1-click Exploit PoC with reproducible cURL**, and more importantly, our **AI Remediation Engine** provides the exact Python/FastAPI code patch enforcing object-level authorization.*
> *We also detected Excessive Data Exposure leaking SSNs and password hashes, unprivileged access to administrative deletion endpoints, and missing rate-limiting."*

**[1:45 - 2:30] Technical Depth & Competitive Advantage:**
> *"What sets SentinelAPI apart from tools like OWASP ZAP or Postman is our **Multi-Persona Dual-Token Matrix**. Rather than random fuzzing, SentinelAPI understands identity contexts to catch authorization vulnerabilities with zero false positives.*
> *Furthermore, with one click on 'Audit Report', engineering leads get a comprehensive, printable executive compliance report aligned with OWASP API Security Top 10 2023."*

**[2:30 - 3:00] Conclusion & Q&A:**
> *"SentinelAPI empowers engineering teams to ship fast without sacrificing security. Thank you, and we welcome your questions!"*

---

## 🛡️ Judges' Cross-Questions & Winning Answers

**Q1: How do you prevent false positives in BOLA/IDOR detection?**
> **Answer**: *"Great question! Generic scanners guess parameters, which causes high false-positive rates. SentinelAPI uses a **Dual-Persona Authentication Matrix**: we make a baseline authenticated request with Persona A to verify a valid 200 OK, and then execute the exact request with Persona B's token. Only when Persona B receives a 200 OK containing Persona A's proprietary resource identifier do we confirm a vulnerability."*

**Q2: Can this run on any API, or only your mock API?**
> **Answer**: *"SentinelAPI is completely specification-agnostic. It accepts any standard OpenAPI 3.0 or Swagger JSON/YAML URL or raw payload. You can paste any live API definition in the Target Config modal and SentinelAPI will map its endpoints and test its security controls."*

**Q3: Does the scanner risk bringing down a live production API?**
> **Answer**: *"SentinelAPI follows zero-trust non-destructive auditing principles. It focuses on authorization checks and data exposure analysis with bounded rate probes rather than destructive payload injection or volumetric DDoS attacks. It is designed to run safely in staging or CI/CD pipelines."*
