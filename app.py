"""
CTF Challenge 2 — SSRF Postman
================================
Vulnerability : Server-Side Request Forgery (SSRF)
Category      : Web
Difficulty    : Hard

Deploy on Railway / Render / Fly.io — no local machine needed.

HOW THE CHALLENGE WORKS:
  - /preview  accepts any URL and fetches it server-side (no filtering)
  - /internal/secret  contains the flag but:
      • blocks ALL browser User-Agents
      • blocks requests NOT from 127.0.0.1
  - Player must submit http://127.0.0.1:<PORT>/internal/secret
    as the preview URL, making the server fetch its own secret.
"""

import os
import requests
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

FLAG = "CTF{ssrf_int3rnal_g0t_pwned}"

# Railway/Render/Fly inject PORT as an env var; fall back to 5000
PORT = int(os.environ.get("PORT", 5000))


# ──────────────────────────────────────────────────────────────
#  ROUTES
# ──────────────────────────────────────────────────────────────

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/preview", methods=["GET", "POST"])
def preview():
    """
    Fetches a user-supplied URL server-side and returns the response.
    ⚠️  Intentionally no SSRF protection — that IS the challenge.
    """
    data = request.get_json(silent=True) or request.form
    url  = (data or {}).get("url") or request.args.get("url", "").strip()

    if not url:
        return jsonify({"error": "Provide a 'url' field in the JSON body."}), 400

    try:
        resp    = requests.get(url, timeout=6, allow_redirects=True)
        content = resp.text[:3000]          # cap to 3000 chars

        # Try to auto-parse JSON so it renders nicely
        try:
            import json
            parsed  = json.loads(content)
            content = json.dumps(parsed, indent=2)
        except Exception:
            pass

        return jsonify({
            "fetched_url":  url,
            "status":       resp.status_code,
            "content_type": resp.headers.get("Content-Type", "unknown"),
            "preview":      content
        })

    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Could not connect to that URL."}), 502
    except requests.exceptions.Timeout:
        return jsonify({"error": "Request timed out after 6 seconds."}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/info")
def info():
    """
    Public endpoint — tells players the app is running.
    'Accidentally' leaks that an internal service exists on the same host.
    Gives players the SSRF target path to try.
    """
    return jsonify({
        "app":    "LinkPreview Pro v1.2",
        "status": "running",
        "note":   "Internal diagnostics service is running on the same host.",
        "path":   "/internal/secret"    # "accidentally" leaked — intended
    })


@app.route("/internal/secret")
def internal_secret():
    """
    Internal-only route — the SSRF target.

    Access rules:
      ✅  Allowed : request from 127.0.0.1, non-browser User-Agent
      ❌  Blocked : direct browser access (Mozilla/Chrome/Safari UA)
      ❌  Blocked : any IP that is not 127.0.0.1
    """
    client_ip  = request.remote_addr
    user_agent = request.headers.get("User-Agent", "")

    # Block non-localhost IPs first
    if client_ip not in ("127.0.0.1", "::1"):
        return jsonify({
            "error":   "403 Forbidden",
            "message": "This is an internal service. Not reachable from the outside. 🤫"
        }), 403

    # Block direct browser visits from localhost too
    browser_signals = ["Mozilla", "Chrome", "Safari", "Firefox", "Edge", "Opera"]
    if any(sig in user_agent for sig in browser_signals):
        return jsonify({
            "error":   "403 Forbidden",
            "message": "Nice try! Browsers not allowed. This endpoint is for internal server use only. 😏",
            "hint":    "What if the *server itself* made the request instead of your browser? 👀"
        }), 403

    # ✅ Server-side request (SSRF success!)
    return jsonify({
        "service": "Internal Metadata Service v1.0",
        "flag":    FLAG,
        "message": "🔥 You SSRFed your way in! The server fetched its own secret for you."
    })


# ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
