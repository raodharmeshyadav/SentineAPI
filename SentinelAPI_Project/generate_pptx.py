"""
SentinelAPI - High-Impact, Story-Driven Hackathon Pitch Deck (10 Slides)
Engineered for AmiHacks 1.0 (Track C: Industry & Deep-Tech)
Crystal-clear storytelling that any judge will immediately understand and love.
"""

from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE
import os

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)

# Apple-Inspired High-Contrast Dark Palette
COLOR_BG = RGBColor(11, 15, 25)        # #0b0f19
COLOR_CARD = RGBColor(17, 24, 39)      # #111827
COLOR_CARD_BORDER = RGBColor(31, 41, 55) # #1f2937
COLOR_BLUE = RGBColor(56, 189, 248)    # #38bdf8 (Sky Blue)
COLOR_RED = RGBColor(244, 63, 94)      # #f43f5e (Rose/Red)
COLOR_GREEN = RGBColor(52, 211, 153)   # #34d399 (Emerald Green)
COLOR_WHITE = RGBColor(248, 250, 252)  # #f8fafc
COLOR_MUTED = RGBColor(148, 163, 184)  # #94a3b8
COLOR_AMBER = RGBColor(251, 191, 36)   # #fbbf24

blank_layout = prs.slide_layouts[6]

def set_bg(slide):
    bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
    bg.fill.solid()
    bg.fill.fore_color.rgb = COLOR_BG
    bg.line.fill.background()

def add_header(slide, tag, title, tag_color=COLOR_BLUE):
    tb = slide.shapes.add_textbox(Inches(0.8), Inches(0.5), Inches(11.73), Inches(1.3))
    tf = tb.text_frame
    tf.word_wrap = True
    
    p_tag = tf.paragraphs[0]
    p_tag.text = tag
    p_tag.font.size = Pt(12)
    p_tag.font.bold = True
    p_tag.font.color.rgb = tag_color
    
    p_title = tf.add_paragraph()
    p_title.text = title
    p_title.font.size = Pt(28)
    p_title.font.bold = True
    p_title.font.color.rgb = COLOR_WHITE

# ==================== SLIDE 1: HOOK & TITLE ====================
s1 = prs.slides.add_slide(blank_layout)
set_bg(s1)

tb1 = s1.shapes.add_textbox(Inches(1.0), Inches(1.6), Inches(11.33), Inches(4.5))
tf1 = tb1.text_frame
tf1.word_wrap = True

p1 = tf1.paragraphs[0]
p1.text = "AMI HACKS 1.0  |  TRACK C: INDUSTRY & DEEP-TECH"
p1.font.size = Pt(13)
p1.font.bold = True
p1.font.color.rgb = COLOR_BLUE

p2 = tf1.add_paragraph()
p2.text = "SentinelAPI"
p2.font.size = Pt(58)
p2.font.bold = True
p2.font.color.rgb = COLOR_WHITE

p3 = tf1.add_paragraph()
p3.text = "The Automated Antivirus for API Data Leaks"
p3.font.size = Pt(24)
p3.font.bold = True
p3.font.color.rgb = COLOR_GREEN

p4 = tf1.add_paragraph()
p4.text = "\nHow changing 1 character in a URL steals millions of private records — and how SentinelAPI detects and patches it in 400 milliseconds."
p4.font.size = Pt(14)
p4.font.color.rgb = COLOR_MUTED

# ==================== SLIDE 2: THE REAL-WORLD PROBLEM ====================
s2 = prs.slides.add_slide(blank_layout)
set_bg(s2)
add_header(s2, "01. THE $100M SECURITY BLINDSPOT", "How 1 Number in a URL Leaks Everything", COLOR_RED)

steps_s2 = [
    ("1. The Normal Request", "User Alice logs into the medical app. Her browser requests:\n\nGET /patients/101\n\nServer responds with Alice's own records. Perfectly safe.", COLOR_BLUE),
    ("2. The Malicious Change", "Alice opens her browser developer tools and changes just 1 number in the URL:\n\nGET /patients/102\n\n(Patient 102 belongs to Bob, a total stranger).", COLOR_AMBER),
    ("3. The Disaster (BOLA)", "The server checks Alice's token, sees she is logged in, and sends Bob's private cancer report and SSN to Alice with 200 OK!\n\nThis is BOLA (Broken Object Level Authorization).", COLOR_RED)
]

for idx, (title, desc, color) in enumerate(steps_s2):
    card = s2.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8 + idx * 3.95), Inches(2.0), Inches(3.8), Inches(4.0))
    card.fill.solid()
    card.fill.fore_color.rgb = COLOR_CARD
    card.line.color.rgb = color
    card.line.width = Pt(1.5)
    ctf = card.text_frame
    ctf.word_wrap = True
    ctf.paragraphs[0].text = title
    ctf.paragraphs[0].font.size = Pt(16)
    ctf.paragraphs[0].font.bold = True
    ctf.paragraphs[0].font.color.rgb = color
    p = ctf.add_paragraph()
    p.text = f"\n{desc}"
    p.font.size = Pt(12)
    p.font.color.rgb = COLOR_MUTED

# Bottom Stat Banner
stat_box = s2.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(6.2), Inches(11.73), Inches(0.8))
stat_box.fill.solid()
stat_box.fill.fore_color.rgb = RGBColor(30, 20, 30)
stat_box.line.color.rgb = COLOR_RED
stat_tf = stat_box.text_frame
stat_tf.word_wrap = True
sp = stat_tf.paragraphs[0]
sp.text = "⚠️ Real World Impact: Over 94% of major API leaks (T-Mobile, Optus, Twitter) happened exactly like this. Not SQL injection."
sp.font.size = Pt(12)
sp.font.bold = True
sp.font.color.rgb = COLOR_RED

# ==================== SLIDE 3: WHY TOOLS ARE BLIND ====================
s3 = prs.slides.add_slide(blank_layout)
set_bg(s3)
add_header(s3, "02. WHY NOBODY CATCHES THIS", "Traditional Scanners Are 100% Blind to Business Logic", COLOR_AMBER)

blind_cards = [
    ("OWASP ZAP / Burp Suite", "Traditional scanners look for syntax errors (SQL injection, XSS tags).\n\nWhen Alice steals Bob's data, the server returns a valid HTTP 200 OK. Standard scanners think it's a happy customer and report 0 errors!", COLOR_MUTED),
    ("Web Firewalls (WAF)", "Firewalls only check IP addresses, rate spikes, and HTTP headers.\n\nThey have zero understanding of database permissions or whether User A owns Resource B. The attack slips right through.", COLOR_MUTED),
    ("Manual Penetration Testing", "Companies hire human security consultants at $15,000 per audit.\n\nIt takes 2-3 weeks to manually test endpoints in Postman. Meanwhile, developers ship code every day without any safety net.", COLOR_RED)
]

for idx, (title, desc, color) in enumerate(blind_cards):
    card = s3.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8 + idx * 3.95), Inches(2.1), Inches(3.8), Inches(4.5))
    card.fill.solid()
    card.fill.fore_color.rgb = COLOR_CARD
    card.line.color.rgb = color
    card.line.width = Pt(1.5)
    ctf = card.text_frame
    ctf.word_wrap = True
    ctf.paragraphs[0].text = title
    ctf.paragraphs[0].font.size = Pt(16)
    ctf.paragraphs[0].font.bold = True
    ctf.paragraphs[0].font.color.rgb = COLOR_WHITE
    p = ctf.add_paragraph()
    p.text = f"\n{desc}"
    p.font.size = Pt(13)
    p.font.color.rgb = COLOR_MUTED

# ==================== SLIDE 4: WHAT IS SENTINEL-API ====================
s4 = prs.slides.add_slide(blank_layout)
set_bg(s4)
add_header(s4, "03. OUR SOLUTION", "SentinelAPI: How We Solve It in 3 Simple Steps", COLOR_GREEN)

solution_steps = [
    ("Step 1: Ingest OpenAPI Spec", "Developers simply point SentinelAPI to their Swagger / OpenAPI JSON URL (e.g. http://localhost:8001/openapi.json). Our engine instantly maps every route, path parameter, and data model.", COLOR_BLUE),
    ("Step 2: Simulate Hacker Identity", "SentinelAPI creates two distinct virtual tenant sessions (Alice and Bob). It automatically tests Alice's credentials against Bob's private URLs. If Bob's data returns with 200 OK, BOLA is confirmed!", COLOR_AMBER),
    ("Step 3: Generate Exploit & Fix", "SentinelAPI doesn't just complain. It gives the developer an instant standalone Python exploit script to reproduce the bug, plus a copy-paste FastAPI code patch that fixes it immediately.", COLOR_GREEN)
]

for idx, (title, desc, color) in enumerate(solution_steps):
    card = s4.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(2.1 + idx * 1.55), Inches(11.73), Inches(1.3))
    card.fill.solid()
    card.fill.fore_color.rgb = COLOR_CARD
    card.line.color.rgb = color
    card.line.width = Pt(1.5)
    ctf = card.text_frame
    ctf.word_wrap = True
    ctf.paragraphs[0].text = title
    ctf.paragraphs[0].font.size = Pt(16)
    ctf.paragraphs[0].font.bold = True
    ctf.paragraphs[0].font.color.rgb = color
    p = ctf.add_paragraph()
    p.text = desc
    p.font.size = Pt(12)
    p.font.color.rgb = COLOR_MUTED

# ==================== SLIDE 5: LIVE TEST COMPARISON ====================
s5 = prs.slides.add_slide(blank_layout)
set_bg(s5)
add_header(s5, "04. EMPIRICAL PROOF", "The Live Hospital API Test: Before vs After", COLOR_BLUE)

# Vulnerable
c_v = s5.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(2.1), Inches(5.75), Inches(4.5))
c_v.fill.solid()
c_v.fill.fore_color.rgb = COLOR_CARD
c_v.line.color.rgb = COLOR_RED
c_v.line.width = Pt(2)
tf_v = c_v.text_frame
tf_v.word_wrap = True
tf_v.paragraphs[0].text = "BEFORE: Vulnerable Sandbox (:8001)"
tf_v.paragraphs[0].font.size = Pt(16)
tf_v.paragraphs[0].font.bold = True
tf_v.paragraphs[0].font.color.rgb = COLOR_RED

pv = tf_v.add_paragraph()
pv.text = "\n• Security Score: 5 / 100 (Grade F)\n• 10 Critical Flaws Detected\n• Alice accessed Bob's patient records & prescriptions\n• Public user profile leaked Bcrypt password hashes and SSNs\n• Non-admin user was able to call DELETE /admin/users/102\n• Zero rate limiting on /auth/login"
pv.font.size = Pt(13)
pv.font.color.rgb = COLOR_MUTED

# Secured
c_s = s5.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.78), Inches(2.1), Inches(5.75), Inches(4.5))
c_s.fill.solid()
c_s.fill.fore_color.rgb = COLOR_CARD
c_s.line.color.rgb = COLOR_GREEN
c_s.line.width = Pt(2)
tf_s = c_s.text_frame
tf_s.word_wrap = True
tf_s.paragraphs[0].text = "AFTER: Hardened Zero-Trust API (:8002)"
tf_s.paragraphs[0].font.size = Pt(16)
tf_s.paragraphs[0].font.bold = True
tf_s.paragraphs[0].font.color.rgb = COLOR_GREEN

ps = tf_s.add_paragraph()
ps.text = "\n• Security Score: 98 / 100 (Grade A+)\n• 0 Vulnerabilities Detected\n• Strict Tenant Scoping: Accessing Bob's record returns 403 Forbidden\n• Filtered DTOs: Password hashes stripped from JSON responses\n• Role-Based Access Control: Admin routes strictly restricted\n• In-Memory Token Bucket: Brute force logins throttled"
ps.font.size = Pt(13)
ps.font.color.rgb = COLOR_MUTED

# ==================== SLIDE 6: KILLER FEATURE 1: VISUAL ATTACK MAP ====================
s6 = prs.slides.add_slide(blank_layout)
set_bg(s6)
add_header(s6, "05. KILLER FEATURE #1", "Visual Attack Map: See the Crime Scene in Real Time", COLOR_BLUE)

map_cards = [
    ("Node 1: Attacker Token", "Alice initiates request using her valid token, requesting Bob's ID (102).", COLOR_BLUE),
    ("Node 2: API Gateway", "Traffic passes through reverse proxy (HTTP formatting is 100% valid).", COLOR_MUTED),
    ("Node 3: Missing Check", "Auth middleware checks token signature, but skips checking who owns ID 102!", COLOR_RED),
    ("Node 4: Target Controller", "Endpoint queries database with raw URL ID without tenant verification.", COLOR_AMBER),
    ("Node 5: Leaked Database", "Bob's private records return to Alice with 200 OK. Crime completed.", COLOR_GREEN)
]

for idx, (title, desc, color) in enumerate(map_cards):
    card = s6.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(2.1 + idx * 0.95), Inches(11.73), Inches(0.82))
    card.fill.solid()
    card.fill.fore_color.rgb = COLOR_CARD
    card.line.color.rgb = color
    card.line.width = Pt(1.5)
    ctf = card.text_frame
    ctf.word_wrap = True
    ctf.paragraphs[0].text = title
    ctf.paragraphs[0].font.size = Pt(13)
    ctf.paragraphs[0].font.bold = True
    ctf.paragraphs[0].font.color.rgb = color
    p = ctf.add_paragraph()
    p.text = desc
    p.font.size = Pt(11)
    p.font.color.rgb = COLOR_MUTED

# ==================== SLIDE 7: KILLER FEATURE 2: EXPLOIT GENERATOR ====================
s7 = prs.slides.add_slide(blank_layout)
set_bg(s7)
add_header(s7, "06. KILLER FEATURE #2", "1-Click Python Exploit Script (Instant Proof-of-Concept)", COLOR_RED)

c7_l = s7.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(2.1), Inches(5.75), Inches(4.5))
c7_l.fill.solid()
c7_l.fill.fore_color.rgb = COLOR_CARD
c7_l.line.color.rgb = COLOR_RED
tf7_l = c7_l.text_frame
tf7_l.word_wrap = True
tf7_l.paragraphs[0].text = "Why Developers Love This"
tf7_l.paragraphs[0].font.size = Pt(16)
tf7_l.paragraphs[0].font.bold = True
tf7_l.paragraphs[0].font.color.rgb = COLOR_WHITE

p7_l = tf7_l.add_paragraph()
p7_l.text = "\n• Security reports without proof get ignored:\nSecurity teams often file vague tickets like 'BOLA vulnerability on /patients'. Developers don't know how to reproduce it and mark it as 'Cannot Reproduce'.\n\n• Instant 1-Click Verification:\nSentinelAPI includes a 'Download Exploit (PoC)' button that generates a clean sentinel_exploit.py file.\n\n• The developer runs it in their terminal in 1 second, sees the exact leaked data, and fixes it immediately."
p7_l.font.size = Pt(13)
p7_l.font.color.rgb = COLOR_MUTED

c7_r = s7.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.78), Inches(2.1), Inches(5.75), Inches(4.5))
c7_r.fill.solid()
c7_r.fill.fore_color.rgb = COLOR_CARD
c7_r.line.color.rgb = COLOR_GREEN
tf7_r = c7_r.text_frame
tf7_r.word_wrap = True
tf7_r.paragraphs[0].text = "Sample Generated Exploit Script"
tf7_r.paragraphs[0].font.size = Pt(16)
tf7_r.paragraphs[0].font.bold = True
tf7_r.paragraphs[0].font.color.rgb = COLOR_WHITE

p7_r = tf7_r.add_paragraph()
p7_r.text = "\n# Standalone Python Exploit\nimport requests\n\ndef test_exploit():\n    headers = {'Authorization': 'Bearer TOKEN_ALICE'}\n    res = requests.get('http://api/patients/102', headers=headers)\n    if res.status_code == 200:\n        print('[+] VULNERABILITY CONFIRMED: Bob data stolen!')\n        print(res.json())\n    else:\n        print('[-] Mitigated: 403 Forbidden')"
p7_r.font.size = Pt(12)
p7_r.font.color.rgb = COLOR_GREEN

# ==================== SLIDE 8: KILLER FEATURE 3: CI/CD GATEKEEPER ====================
s8 = prs.slides.add_slide(blank_layout)
set_bg(s8)
add_header(s8, "07. KILLER FEATURE #3", "CI/CD Gatekeeper: Stopping Bugs Before Production", COLOR_AMBER)

cicd_points = [
    ("Developer Writes Code", "A software engineer adds a new endpoint to the API and pushes to GitHub (e.g. git push origin feature/records).", COLOR_BLUE),
    ("GitHub Actions Triggers SentinelAPI", "In the CI pipeline, python cli.py --target http://staging-api runs automatically in 400 milliseconds.", COLOR_AMBER),
    ("Insecure PR Blocked (Exit Code 1)", "If any BOLA or PII vulnerability is detected, SentinelAPI returns exit code 1, automatically FAILING the build and preventing merging into production!", COLOR_RED)
]

for idx, (title, desc, color) in enumerate(cicd_points):
    card = s8.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8 + idx * 3.95), Inches(2.1), Inches(3.8), Inches(4.5))
    card.fill.solid()
    card.fill.fore_color.rgb = COLOR_CARD
    card.line.color.rgb = color
    card.line.width = Pt(1.5)
    ctf = card.text_frame
    ctf.word_wrap = True
    ctf.paragraphs[0].text = title
    ctf.paragraphs[0].font.size = Pt(16)
    ctf.paragraphs[0].font.bold = True
    ctf.paragraphs[0].font.color.rgb = COLOR_WHITE
    p = ctf.add_paragraph()
    p.text = f"\n{desc}"
    p.font.size = Pt(13)
    p.font.color.rgb = COLOR_MUTED

# ==================== SLIDE 9: COMPETITIVE ADVANTAGE ====================
s9 = prs.slides.add_slide(blank_layout)
set_bg(s9)
add_header(s9, "08. WHY WE WIN", "SentinelAPI vs Traditional Alternatives", COLOR_GREEN)

matrix_data = [
    ("Metric / Feature", "Manual Pen Testing", "OWASP ZAP / Burp", "SentinelAPI"),
    ("BOLA / IDOR Detection", "Yes (Slow & Incomplete)", "No (0% Logic Support)", "100% Deterministic Dual-Token"),
    ("Audit Speed", "2 - 3 Weeks", "15 - 30 Minutes", "400 Milliseconds"),
    ("Exploit Script Generator", "No (Manual Writeup)", "No", "Yes (1-Click Python PoC)"),
    ("Visual Attack DAG Map", "No", "No", "Yes (Interactive Topology)"),
    ("Remediation Code Fixes", "Generic Guidelines", "None", "Ready-to-Paste FastAPI Code"),
    ("Cost per Audit", "$15,000+ per engagement", "Open Source / Heavy Java", "Free & Open Source")
]

rows = len(matrix_data)
cols = 4
t_shape = s9.shapes.add_table(rows, cols, Inches(0.8), Inches(2.1), Inches(11.73), Inches(4.5))
table = t_shape.table

table.columns[0].width = Inches(3.3)
table.columns[1].width = Inches(2.8)
table.columns[2].width = Inches(2.8)
table.columns[3].width = Inches(2.83)

for r_idx, row in enumerate(matrix_data):
    for c_idx, val in enumerate(row):
        cell = table.cell(r_idx, c_idx)
        cell.fill.solid()
        if r_idx == 0:
            cell.fill.fore_color.rgb = COLOR_BLUE
        elif c_idx == 3:
            cell.fill.fore_color.rgb = RGBColor(16, 40, 30)
        else:
            cell.fill.fore_color.rgb = COLOR_CARD
            
        p = cell.text_frame.paragraphs[0]
        p.text = val
        p.font.size = Pt(12)
        p.font.bold = (r_idx == 0 or c_idx == 3)
        if c_idx == 3 and r_idx > 0:
            p.font.color.rgb = COLOR_GREEN
        elif r_idx == 0:
            p.font.color.rgb = COLOR_WHITE
        else:
            p.font.color.rgb = COLOR_MUTED

# ==================== SLIDE 10: TEAM & LIVE DEMO ====================
s10 = prs.slides.add_slide(blank_layout)
set_bg(s10)
add_header(s10, "09. THE TEAM & DEMO", "Real Engineering, Real Ownership", COLOR_BLUE)

team_members = [
    ("Lead Security Researcher", "Team Lead", "Authored core scanner heuristics, dual-token permutation logic, and exploit script generator."),
    ("Backend Systems Engineer", "Core Dev", "Built FastAPI orchestration server and realistic Vulnerable (:8001) & Secured (:8002) sandbox APIs."),
    ("Frontend UI/UX Engineer", "Interface Dev", "Designed Apple-grade glassmorphic dashboard, Light/Dark modes, and interactive Vis.js DAG topology."),
    ("DevSecOps & QA Engineer", "Tooling & CI/CD", "Engineered terminal CLI tool (cli.py), automated PDF report generator, and Git workflows.")
]

for idx, (name, role, work) in enumerate(team_members):
    card = s10.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8 + idx * 2.95), Inches(2.1), Inches(2.8), Inches(3.6))
    card.fill.solid()
    card.fill.fore_color.rgb = COLOR_CARD
    card.line.color.rgb = COLOR_BLUE if idx == 0 else COLOR_CARD_BORDER
    card.line.width = Pt(1.5)
    ctf = card.text_frame
    ctf.word_wrap = True
    ctf.paragraphs[0].text = name
    ctf.paragraphs[0].font.size = Pt(14)
    ctf.paragraphs[0].font.bold = True
    ctf.paragraphs[0].font.color.rgb = COLOR_WHITE
    p_r = ctf.add_paragraph()
    p_r.text = role
    p_r.font.size = Pt(11)
    p_r.font.color.rgb = COLOR_BLUE
    p_w = ctf.add_paragraph()
    p_w.text = f"\n{work}"
    p_w.font.size = Pt(11)
    p_w.font.color.rgb = COLOR_MUTED

# Call to Action Banner
cta_box = s10.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(6.0), Inches(11.73), Inches(0.95))
cta_box.fill.solid()
cta_box.fill.fore_color.rgb = RGBColor(16, 50, 40)
cta_box.line.color.rgb = COLOR_GREEN
cta_tf = cta_box.text_frame
cta_tf.word_wrap = True
cp = cta_tf.paragraphs[0]
cp.text = "🚀 Don't just take our word for it — let's see the live attack and audit in 30 seconds!"
cp.font.size = Pt(15)
cp.font.bold = True
cp.font.color.rgb = COLOR_GREEN

output_path = os.path.join(os.path.dirname(__file__), "SentinelAPI_Presentation.pptx")
prs.save(output_path)
print(f"[+] Successfully generated high-impact 10-slide pitch deck: {output_path}")
