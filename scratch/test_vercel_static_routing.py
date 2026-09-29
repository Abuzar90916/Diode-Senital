"""
Local Static Server Test for Vercel Rewrites
Simulates the exact Vercel v2 static routing engine using vercel.json.
Tests all endpoints requested by the user:
- GET /dashboard/overview
- GET /dashboard/static/style.css
- GET /dashboard/static/app.js
- GET /static/style.css
- GET /static/app.js
- GET /dashboard
- GET /
"""

import os
import re
import json
import http.server
import socketserver
import threading
import urllib.request
import mimetypes

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Load vercel.json
with open(os.path.join(BASE_DIR, "vercel.json"), "r") as f:
    vercel_cfg = json.load(f)

rewrites = vercel_cfg.get("rewrites", [])
headers_rules = vercel_cfg.get("headers", [])

class VercelStaticSimulatorHandler(http.server.BaseHTTPRequestHandler):
    def resolve_url(self, path):
        # Apply rewrites in order
        target_path = path
        matched_rule = None
        for rule in rewrites:
            pattern = "^" + rule["source"] + "$"
            match = re.match(pattern, path)
            if match:
                dest = rule["destination"]
                # Substitute capture groups ($1, etc.)
                for idx, group in enumerate(match.groups(), start=1):
                    dest = dest.replace(f"${idx}", group or "")
                target_path = dest
                matched_rule = rule
                break
        return target_path, matched_rule

    def get_custom_headers(self, path):
        custom = {}
        for h_rule in headers_rules:
            pattern = "^" + h_rule["source"] + "$"
            if re.match(pattern, path):
                for h in h_rule.get("headers", []):
                    custom[h["key"]] = h["value"]
        return custom

    def do_GET(self):
        resolved_path, rule = self.resolve_url(self.path)
        
        # Map resolved path to file on disk
        clean_rel = resolved_path.lstrip("/")
        file_path = os.path.join(BASE_DIR, clean_rel)

        if not os.path.exists(file_path) or os.path.isdir(file_path):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found in Vercel Simulator")
            return

        # Determine MIME type
        ctype = None
        custom_h = self.get_custom_headers(self.path)
        if "Content-Type" in custom_h:
            ctype = custom_h["Content-Type"]
        elif file_path.endswith(".css"):
            ctype = "text/css; charset=utf-8"
        elif file_path.endswith(".js"):
            ctype = "application/javascript; charset=utf-8"
        elif file_path.endswith(".html"):
            ctype = "text/html; charset=utf-8"
        else:
            ctype, _ = mimetypes.guess_type(file_path)
            if not ctype:
                ctype = "application/octet-stream"

        with open(file_path, "rb") as f:
            content = f.read()

        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(content)))
        for k, v in custom_h.items():
            if k != "Content-Type":
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format, *args):
        pass  # Quiet logs during test

def run_tests():
    # Start server on dynamic port
    with socketserver.TCPServer(("127.0.0.1", 0), VercelStaticSimulatorHandler) as httpd:
        port = httpd.server_address[1]
        server_thread = threading.Thread(target=httpd.serve_forever)
        server_thread.daemon = True
        server_thread.start()

        base_url = f"http://127.0.0.1:{port}"
        print(f"[*] Vercel static routing test server listening on {base_url}")

        tests = [
            # path, expected_status, expected_mime, forbidden_substr
            ("/dashboard/overview", 200, "text/html", None),
            ("/dashboard", 200, "text/html", None),
            ("/", 200, "text/html", None),
            ("/dashboard/static/style.css", 200, "text/css", "<!DOCTYPE html>"),
            ("/dashboard/static/app.js", 200, "application/javascript", "<!DOCTYPE html>"),
            ("/static/style.css", 200, "text/css", "<!DOCTYPE html>"),
            ("/static/app.js", 200, "application/javascript", "<!DOCTYPE html>"),
        ]

        all_passed = True
        for path, exp_code, exp_mime, forbidden in tests:
            req_url = f"{base_url}{path}"
            req = urllib.request.Request(req_url)
            try:
                with urllib.request.urlopen(req) as resp:
                    code = resp.getcode()
                    content_type = resp.headers.get("Content-Type", "")
                    body = resp.read().decode("utf-8", errors="replace")

                    # Verify status code
                    assert code == exp_code, f"Expected {exp_code}, got {code}"
                    
                    # Verify MIME
                    assert exp_mime in content_type, f"Expected MIME {exp_mime}, got {content_type}"
                    
                    # Verify asset does not return HTML
                    if forbidden:
                        assert forbidden not in body, f"ERROR: Asset returned HTML content on {path}!"

                    print(f"  [PASS] {path:30} -> HTTP {code} ({content_type}) [{len(body)} bytes]")
            except Exception as e:
                print(f"  [FAIL] {path:30} -> {e}")
                all_passed = False

        httpd.shutdown()
        if all_passed:
            print("\n[+] ALL VERCEL STATIC ASSET ROUTING TESTS PASSED!")
            return 0
        else:
            print("\n[-] SOME TESTS FAILED!")
            return 1

if __name__ == "__main__":
    import sys
    sys.exit(run_tests())
