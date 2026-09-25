"""
SentinelAPI - Unified Launcher
Starts:
1. Target Vulnerable Sandbox API (Port 8001)
2. Target Remediated / Secured API (Port 8002)
3. SentinelAPI Management Engine & Dashboard (Port 8000)
"""

import subprocess
import sys
import time
import webbrowser
import os

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

def main():
    root_dir = os.path.dirname(os.path.abspath(__file__))
    print("\n" + "=" * 65)
    print("      [SENTINEL-API] OPENAPI SECURITY TEST SUITE")
    print("             AMI HACKS 1.0 - TRACK C")
    print("=" * 65)
    
    # 1. Start Vulnerable Target API on port 8001
    print("[*] Starting Vulnerable Target API on http://127.0.0.1:8001 ...")
    vuln_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "target_api.app:app", "--host", "127.0.0.1", "--port", "8001"],
        cwd=root_dir
    )

    # 2. Start Remediated / Secured Target API on port 8002
    print("[*] Starting Secured Target API on http://127.0.0.1:8002 ...")
    secure_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "target_api.app_secure:app", "--host", "127.0.0.1", "--port", "8002"],
        cwd=root_dir
    )

    # 3. Start SentinelAPI Management Server on port 8000
    print("[*] Starting SentinelAPI Test Dashboard on http://127.0.0.1:8000 ...")
    server_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.server:app", "--host", "127.0.0.1", "--port", "8000"],
        cwd=root_dir
    )

    print("[*] Initializing services...")
    time.sleep(2.5)

    dashboard_url = "http://127.0.0.1:8000"
    print(f"\n[+] SUCCESS! Dashboard running at: {dashboard_url}")
    print(f"[+] Vulnerable Target (Port 8001): http://127.0.0.1:8001/docs")
    print(f"[+] Remediated Target (Port 8002): http://127.0.0.1:8002/docs")
    print(f"[+] Presentation Slides:          {dashboard_url}/slides")
    print(f"[+] Submission PDF Report:        {dashboard_url}/report")
    
    try:
        webbrowser.open(dashboard_url)
    except Exception:
        pass

    print("\n[*] SentinelAPI is actively running. Press Ctrl+C in terminal to stop.")
    try:
        server_proc.wait()
    except KeyboardInterrupt:
        print("\n[*] Stopping SentinelAPI services...")
        vuln_proc.terminate()
        secure_proc.terminate()
        server_proc.terminate()
        print("[+] Services stopped.")

if __name__ == "__main__":
    main()
