"""GitHub Sentinel v3 — Flask Application."""
import os, csv, io, json, logging, functools
from flask import Flask, render_template, request, jsonify, Response, session, redirect

from core.db import (
    init_db, get_job, get_all_jobs, get_findings, get_repo_result,
    get_all_repo_results, get_alert_log, suppress_finding,
    get_global_stats, now_iso,
)
from core.scanner import create_job, cancel_job, discover_repos
from core.github  import parse_repo_input, get_rate_limit, get_user_info
from core.patterns import SECRET_PATTERNS, calculate_risk_score
from core.alerts  import send_email, send_webhook, send_github_issues, build_html_report

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SENTINEL_SECRET", os.urandom(32))

# Single shared password — set via env or default for dev
SENTINEL_PASSWORD = os.environ.get("SENTINEL_PASSWORD")

# ── Init DB on startup ─────────────────────────────────────────────────────────
with app.app_context():
    init_db()


# ── Auth ───────────────────────────────────────────────────────────────────────
def require_auth(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("authenticated"):
            if request.is_json:
                return jsonify({"error": "Not authenticated"}), 401
            return render_template("login.html"), 401
        return f(*args, **kwargs)
    return wrapper

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        data = request.get_json(silent=True, force=True) or {}
        pw   = request.form.get("password") or data.get("password", "")
        if pw == SENTINEL_PASSWORD:
            session["authenticated"] = True
            if request.is_json:
                return jsonify({"ok": True})
            return redirect("/")
        if request.is_json:
            return jsonify({"error": "Wrong password"}), 401
        return render_template("login.html", error="Wrong password"), 401
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ── Pages ──────────────────────────────────────────────────────────────────────
@app.route("/")
@require_auth
def index():
    return render_template("index.html")


# ── API: system ────────────────────────────────────────────────────────────────
@app.route("/api/stats")
@require_auth
def api_stats():
    return jsonify(get_global_stats())

@app.route("/api/ratelimit")
@require_auth
def api_ratelimit():
    token = request.args.get("token","").strip() or None
    return jsonify(get_rate_limit(token))


# ── API: discover ──────────────────────────────────────────────────────────────
@app.route("/api/discover", methods=["POST"])
@require_auth
def api_discover():
    d      = request.get_json(force=True)
    handle = d.get("handle","").strip()
    token  = d.get("token","").strip() or None
    max_r  = min(int(d.get("max_repos",50)), 200)
    if not handle:
        return jsonify({"error": "handle required"}), 400
    info = get_user_info(handle, token)
    if not info:
        return jsonify({"error": f"'{handle}' not found on GitHub"}), 404
    repos = discover_repos(handle, token, max_repos=max_r)
    return jsonify({
        "handle": handle, "type": info.get("type","User"),
        "avatar": info.get("avatar_url",""), "name": info.get("name") or handle,
        "bio": info.get("bio") or "", "public_repos": info.get("public_repos",0),
        "repos": [{"owner":o,"repo":r,"full_name":f"{o}/{r}"} for o,r in repos],
    })


# ── API: scan ──────────────────────────────────────────────────────────────────
@app.route("/api/scan", methods=["POST"])
@require_auth
def api_scan():
    d           = request.get_json(force=True)
    token       = d.get("token","").strip() or None
    raw_targets = d.get("targets", [])
    scan_history= bool(d.get("scan_history", False))

    if not raw_targets:
        return jsonify({"error": "No targets"}), 400
    if len(raw_targets) > 200:
        return jsonify({"error": "Max 200 repos per job"}), 400

    targets, bad = [], []
    for t in raw_targets:
        p = parse_repo_input(str(t))
        if p: targets.append(p)
        else: bad.append(t)

    if not targets:
        return jsonify({"error": "No valid targets", "invalid": bad}), 400

    job_id = create_job(targets, token, scan_history=scan_history)
    return jsonify({"job_id": job_id, "queued": len(targets), "invalid": bad})


# ── API: job management ────────────────────────────────────────────────────────
@app.route("/api/job/<job_id>")
@require_auth
def api_job(job_id):
    j = get_job(job_id)
    return jsonify(j) if j else (jsonify({"error":"Not found"}), 404)

@app.route("/api/job/<job_id>/cancel", methods=["POST"])
@require_auth
def api_cancel(job_id):
    ok = cancel_job(job_id)
    return jsonify({"cancelled": ok})

@app.route("/api/job/<job_id>/results")
@require_auth
def api_job_results(job_id):
    include_suppressed = request.args.get("suppressed","0") == "1"
    results = get_all_repo_results(job_id)
    if not include_suppressed:
        for r in results:
            r["findings"] = [f for f in r.get("findings",[]) if not f.get("suppressed")]
    return jsonify(results)

@app.route("/api/jobs")
@require_auth
def api_jobs():
    return jsonify(get_all_jobs())


# ── API: findings ──────────────────────────────────────────────────────────────
@app.route("/api/findings/<job_id>")
@require_auth
def api_findings(job_id):
    repo   = request.args.get("repo")
    sev    = request.args.get("min_severity")
    inc_sup= request.args.get("suppressed","0") == "1"
    return jsonify(get_findings(job_id, repo, sev, inc_sup))

@app.route("/api/suppress", methods=["POST"])
@require_auth
def api_suppress():
    d  = request.get_json(force=True)
    fp = d.get("fingerprint","")
    if not fp: return jsonify({"error":"fingerprint required"}), 400
    suppress_finding(fp, d.get("reason",""))
    return jsonify({"suppressed": fp})


# ── API: alerts ────────────────────────────────────────────────────────────────
@app.route("/api/alert/email", methods=["POST"])
@require_auth
def api_alert_email():
    d         = request.get_json(force=True)
    job_id    = d.get("job_id","")
    recipient = d.get("email","").strip()
    smtp_cfg  = d.get("smtp", {})
    repo_filter = d.get("repos")

    if not recipient: return jsonify({"error":"email required"}), 400
    results = get_all_repo_results(job_id)
    if not results: return jsonify({"error":"No results for job"}), 404
    if repo_filter:
        results = [r for r in results if r.get("full_name") in repo_filter]
    results = [r for r in results if r.get("summary",{}).get("total_findings",0) > 0]
    if not results:
        return jsonify({"message":"No findings to report — all repos are clean!"}), 200

    ok, payload = send_email(results, recipient, smtp_cfg, job_id)
    if not ok: return jsonify({"error": payload}), 500
    if payload.startswith("<!DOCTYPE"):
        return jsonify({"preview_html": payload})
    return jsonify({"success": True, "message": payload})

@app.route("/api/alert/webhook", methods=["POST"])
@require_auth
def api_alert_webhook():
    d   = request.get_json(force=True)
    url = d.get("webhook_url","").strip()
    job_id = d.get("job_id","")
    if not url: return jsonify({"error":"webhook_url required"}), 400
    results = get_all_repo_results(job_id)
    results = [r for r in results if r.get("summary",{}).get("total_findings",0) > 0]
    ok, msg = send_webhook(results, url, job_id)
    return jsonify({"success": ok, "message": msg})

@app.route("/api/alert/github-issues", methods=["POST"])
@require_auth
def api_alert_github():
    d      = request.get_json(force=True)
    token  = d.get("token","").strip()
    job_id = d.get("job_id","")
    if not token: return jsonify({"error":"GitHub token required to create issues"}), 400
    results = get_all_repo_results(job_id)
    results = [r for r in results if r.get("summary",{}).get("total_findings",0) > 0]
    result  = send_github_issues(results, token, job_id)
    return jsonify(result)

@app.route("/api/alert/log")
@require_auth
def api_alert_log():
    job_id = request.args.get("job_id")
    return jsonify(get_alert_log(job_id))


# ── API: export ────────────────────────────────────────────────────────────────
@app.route("/api/export/<job_id>/csv")
@require_auth
def export_csv(job_id):
    findings = get_findings(job_id)
    out = io.StringIO()
    w   = csv.DictWriter(out, fieldnames=[
        "job_id","repo_full_name","severity","type","category","confidence",
        "file_path","line_number","masked_value","entropy","is_test_file",
        "remediation","docs_url","fingerprint","first_seen"
    ])
    w.writeheader()
    for f in findings:
        w.writerow({k: f.get(k,"") for k in w.fieldnames})
    return Response(out.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=sentinel_{job_id}.csv"})

@app.route("/api/export/<job_id>/json")
@require_auth
def export_json(job_id):
    results = get_all_repo_results(job_id)
    return Response(
        json.dumps(results, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=sentinel_{job_id}.json"}
    )

@app.route("/api/export/<job_id>/report")
@require_auth
def export_report(job_id):
    results = get_all_repo_results(job_id)
    results = [r for r in results if r.get("summary",{}).get("total_findings",0) > 0]
    html    = build_html_report(results, "security-report")
    return Response(html, mimetype="text/html",
        headers={"Content-Disposition": f"attachment; filename=sentinel_report_{job_id}.html"})


# ── API: patterns ──────────────────────────────────────────────────────────────
@app.route("/api/patterns")
@require_auth
def api_patterns():
    return jsonify([
        {"name":k, "severity":v["severity"], "category":v["category"],
         "description":v["description"], "remediation":v["remediation"],
         "min_entropy":v.get("min_entropy",0)}
        for k,v in SECRET_PATTERNS.items()
    ])


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)
