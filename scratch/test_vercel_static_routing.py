"""
Production-Equivalent Local Static Routing Acceptance Test
Simulates Vercel's static asset resolution from public/ and SPA rewrites from vercel.json.
Validates:
- GET /static/style.css -> HTTP 200, Content-Type: text/css, starts with CSS, NO '<!DOCTYPE html>'
- GET /static/app.js -> HTTP 200, Content-Type: application/javascript, NO '<!DOCTYPE html>'
- GET /dashboard/static/style.css -> HTTP 200, Content-Type: text/css, NO '<!DOCTYPE html>'
- GET /dashboard/static/app.js -> HTTP 200, Content-Type: application/javascript, NO '<!DOCTYPE html>'
- GET /dashboard/overview -> HTTP 200, actual index.html
- GET /dashboard/threats -> HTTP 200, actual index.html
- GET /dashboard/incidents -> HTTP 200, actual index.html
- GET /dashboard/flows -> HTTP 200, actual index.html
- GET /dashboard/engine -> HTTP 200, actual index.html
- GET /dashboard/demo -> HTTP 200, actual index.html
- GET /dashboard/system -> HTTP 200, actual index.html
- GET /dashboard -> HTTP 200, actual index.html
- GET / -> HTTP 200, actual index.html
"""

import os
import re
import json
import http.server
import socketserver
import threading
import urllib.request
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PUBLIC_DIR = os.path.join(BASE_DIR, "public")

with open(os.path.join(BASE_DIR, "vercel.json"), "r") as f:
    vercel_cfg = json.load(f)

rewrites = vercel_cfg.get("rewrites", [])
headers_rules = vercel_cfg.get("headers", [])

class VercelProductionSimulatorHandler(http.server.BaseHTTPRequestHandler):
    def resolve_path(self, req_path):
        clean_path = req_path.split("?")[0]
        
        # 1. Direct static file in public/ directory (highest precedence in Vercel)
        rel_path = clean_path.lstrip("/")
        direct_file = os.path.join(PUBLIC_DIR, rel_path)
        if os.path.isfile(direct_file):
            return direct_file, False

        # 2. Check rewrites
        for rule in rewrites:
            pattern = "^" + rule["source"] + "$"
            match = re.match(pattern, clean_path)
            if match:
                dest = rule["destination"].lstrip("/")
                rewritten_file = os.path.join(PUBLIC_DIR, dest)
                if os.path.isfile(rewritten_file):
                    return rewritten_file, True

        return None, False

    def get_custom_headers(self, path):
        custom = {}
        for h_rule in headers_rules:
            pattern = "^" + h_rule["source"] + "$"
            if re.match(pattern, path):
                for h in h_rule.get("headers", []):
                    custom[h["key"]] = h["value"]
        return custom

    def do_GET(self):
        file_path, is_rewrite = self.resolve_path(self.path)

        if not file_path or not os.path.exists(file_path):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")
            return

        # Determine MIME
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
            ctype = "application/octet-stream"

        with open(file_path, "rb") as f:
            content = f.read()

        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format, *args):
        pass

def run_acceptance_tests():
    with socketserver.TCPServer(("127.0.0.1", 0), VercelProductionSimulatorHandler) as httpd:
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever)
        t.daemon = True
        t.start()

        base = f"http://127.0.0.1:{port}"
        print(f"[*] Testing against Vercel simulator on {base}\n")

        tests = [
            # path, exp_code, exp_mime_substr, must_contain, must_not_contain
            ("/static/style.css", 200, "text/css", ":root", "<!DOCTYPE html>"),
            ("/static/app.js", 200, "javascript", "DiodeSentinelApp", "<!DOCTYPE html>"),
            ("/dashboard/static/style.css", 200, "text/css", ":root", "<!DOCTYPE html>"),
            ("/dashboard/static/app.js", 200, "javascript", "DiodeSentinelApp", "<!DOCTYPE html>"),
            ("/dashboard/overview", 200, "text/html", "<!DOCTYPE html>", None),
            ("/dashboard/threats", 200, "text/html", "<!DOCTYPE html>", None),
            ("/dashboard/incidents", 200, "text/html", "<!DOCTYPE html>", None),
            ("/dashboard/flows", 200, "text/html", "<!DOCTYPE html>", None),
            ("/dashboard/engine", 200, "text/html", "<!DOCTYPE html>", None),
            ("/dashboard/demo", 200, "text/html", "<!DOCTYPE html>", None),
            ("/dashboard/system", 200, "text/html", "<!DOCTYPE html>", None),
            ("/dashboard", 200, "text/html", "<!DOCTYPE html>", None),
            ("/", 200, "text/html", "<!DOCTYPE html>", None),
        ]

        failed = 0
        for path, exp_code, exp_mime, must_have, must_not_have in tests:
            req = urllib.request.Request(f"{base}{path}")
            try:
                with urllib.request.urlopen(req) as resp:
                    code = resp.getcode()
                    ctype = resp.headers.get("Content-Type", "")
                    body = resp.read().decode("utf-8", errors="replace")

                    assert code == exp_code, f"Expected HTTP {exp_code}, got {code}"
                    assert exp_mime in ctype, f"Expected MIME '{exp_mime}', got '{ctype}'"
                    if must_have:
                        assert must_have in body, f"Body missing expected substring '{must_have}'"
                    if must_not_have:
                        assert must_not_have not in body, f"CRITICAL REGRESSION: Body contains forbidden '{must_not_have}'!"

                    preview = body.strip().split("\n")[0][:45]
                    print(f"  [PASS] {path:32} -> HTTP {code} ({ctype.split(';')[0]:18}) '{preview}...'")
            except Exception as e:
                print(f"  [FAIL] {path:32} -> {e}")
                failed += 1

        httpd.shutdown()
        if failed == 0:
            print(f"\n[+] ALL {len(tests)} ACCEPTANCE TESTS PASSED WITH 100% PRECISION!")
            return 0
        else:
            print(f"\n[-] {failed} TESTS FAILED!")
            return 1

if __name__ == "__main__":
    sys.exit(run_acceptance_tests())
