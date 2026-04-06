"""
Alert system — v3.
Channels: Email (SMTP), Webhook (POST), GitHub Issue creation.
All alerts logged to DB audit trail.
"""
import smtplib, requests, json, logging
from email.mime.multipart import MIMEMultipart
from email.mime.text       import MIMEText
from core.db import log_alert
from core.github import create_security_issue

log = logging.getLogger(__name__)


# ── Shared HTML builder ────────────────────────────────────────────────────────
def _sev_style(sev):
    return {
        "critical": ("background:#3d0000;color:#ff8a8a;border:1px solid #660000",),
        "high":     ("background:#3d1a00;color:#ffb84d;border:1px solid #663000",),
        "medium":   ("background:#3d3000;color:#ffe066;border:1px solid #665000",),
        "low":      ("background:#003d1e;color:#66ffaa;border:1px solid #006633",),
    }.get(sev, ("background:#1e293b;color:#94a3b8",))[0]


def build_html_report(results: list[dict], recipient: str) -> str:
    total_f = sum(r.get("summary",{}).get("total_findings",0) for r in results)
    agg = {"critical":0,"high":0,"medium":0,"low":0}
    for r in results:
        for s,c in r.get("summary",{}).get("severity_counts",{}).items():
            agg[s] = agg.get(s,0) + c

    rows_html = ""
    for res in sorted(results, key=lambda x: -x.get("summary",{}).get("risk_score",0)):
        info  = res.get("repo_info",{})
        summ  = res.get("summary",{})
        sc    = summ.get("severity_counts",{})
        risk  = summ.get("risk_score",0)
        diff  = res.get("diff") or {}
        rc    = "#ef4444" if risk>=70 else "#f97316" if risk>=35 else "#eab308" if risk>0 else "#22c55e"

        diff_html = ""
        if diff:
            diff_html = f"""
            <div style="padding:8px 18px;background:#0a1628;font-size:11px;font-family:monospace;color:#64748b;">
              <span style="color:#22c55e">▲ {diff.get('new',[]).__len__()} new</span>
              &nbsp;·&nbsp;
              <span style="color:#ef4444">▼ {diff.get('fixed',[]).__len__()} fixed</span>
              &nbsp;·&nbsp;
              <span style="color:#94a3b8">= {diff.get('persisted',[]).__len__()} unchanged</span>
            </div>"""

        fhtml = ""
        for f in res.get("findings",[])[:10]:
            st = _sev_style(f["severity"])
            hist_tag = ' <span style="font-size:9px;color:#f97316">[history]</span>' if f.get("from_history") else ""
            conf_tag = f' <span style="font-size:9px;color:#94a3b8">[{f.get("confidence","?")} confidence]</span>' if f.get("confidence") != "high" else ""
            fhtml += f"""
            <tr>
              <td style="padding:7px 10px;border-bottom:1px solid #1e293b;white-space:nowrap">
                <span style="{st};padding:2px 7px;border-radius:4px;font-size:9px;font-weight:700;font-family:monospace">{f['severity'].upper()}</span>
              </td>
              <td style="padding:7px 10px;border-bottom:1px solid #1e293b;color:#e2e8f0;font-size:12px">{f['type']}{hist_tag}{conf_tag}</td>
              <td style="padding:7px 10px;border-bottom:1px solid #1e293b;color:#64748b;font-family:monospace;font-size:11px">{f.get('file_path') or f.get('file','')}:{f.get('line_number') or f.get('line','')}</td>
              <td style="padding:7px 10px;border-bottom:1px solid #1e293b;color:#94a3b8;font-size:11px">{f.get('remediation','')[:90]}</td>
            </tr>"""

        overflow = summ.get("total_findings",0) - 10
        if overflow > 0:
            fhtml += f'<tr><td colspan="4" style="padding:8px 10px;color:#6366f1;font-size:12px;text-align:center">…and {overflow} more findings</td></tr>'

        rows_html += f"""
        <div style="background:#111827;border:1px solid #1e293b;border-left:4px solid {rc};border-radius:8px;margin-bottom:16px;overflow:hidden">
          <div style="padding:14px 18px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #1e293b;flex-wrap:wrap;gap:8px">
            <div>
              <a href="{info.get('html_url','#')}" style="color:#f1f5f9;font-size:15px;font-weight:700;text-decoration:none">
                {res.get('full_name','?')}
              </a>
              <span style="color:#64748b;font-size:12px;margin-left:10px">{info.get('language','?')} · ⭐ {info.get('stars',0)}</span>
            </div>
            <span style="background:{rc}22;color:{rc};border:1px solid {rc}55;padding:3px 12px;border-radius:999px;font-weight:700;font-size:12px">Risk {risk}/100</span>
          </div>
          {diff_html}
          <div style="padding:10px 18px;display:flex;gap:14px;flex-wrap:wrap">
            <span style="color:#ff8a8a;font-size:12px">🔴 {sc.get('critical',0)} Critical</span>
            <span style="color:#ffb84d;font-size:12px">🟠 {sc.get('high',0)} High</span>
            <span style="color:#ffe066;font-size:12px">🟡 {sc.get('medium',0)} Medium</span>
            <span style="color:#64748b;font-size:12px">📄 {summ.get('files_scanned',0)} files</span>
            {"<span style='color:#f97316;font-size:12px'>📜 History scanned</span>" if summ.get('history_scanned') else ""}
          </div>
          {f'''<table style="width:100%;border-collapse:collapse"><thead><tr style="background:#0f172a">
            <th style="padding:8px 10px;text-align:left;color:#475569;font-size:9px;letter-spacing:1px">SEV</th>
            <th style="padding:8px 10px;text-align:left;color:#475569;font-size:9px;letter-spacing:1px">TYPE</th>
            <th style="padding:8px 10px;text-align:left;color:#475569;font-size:9px;letter-spacing:1px">LOCATION</th>
            <th style="padding:8px 10px;text-align:left;color:#475569;font-size:9px;letter-spacing:1px">ACTION</th>
          </tr></thead><tbody>{fhtml}</tbody></table>''' if fhtml else ""}
        </div>"""

    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8"/></head>
<body style="margin:0;padding:20px;background:#030712;font-family:Arial,sans-serif">
<div style="max-width:900px;margin:0 auto">
  <div style="background:linear-gradient(135deg,#7f1d1d,#1e1b4b);border-radius:12px 12px 0 0;padding:30px;text-align:center">
    <div style="font-size:36px;margin-bottom:6px">🛡️</div>
    <h1 style="color:#fff;margin:0;font-size:22px">GitHub Sentinel — Security Report</h1>
    <p style="color:#fca5a5;margin:6px 0 0;font-size:13px">Exposed secrets detected across your repositories</p>
  </div>
  <div style="background:#111827;border:1px solid #1e293b;border-top:none;padding:18px 24px;margin-bottom:16px;display:flex;gap:28px;flex-wrap:wrap">
    <div style="text-align:center"><div style="font-size:28px;font-weight:700;color:#f1f5f9;font-family:monospace">{len(results)}</div><div style="font-size:10px;color:#64748b;letter-spacing:1px">REPOS</div></div>
    <div style="text-align:center"><div style="font-size:28px;font-weight:700;color:#ef4444;font-family:monospace">{total_f}</div><div style="font-size:10px;color:#64748b;letter-spacing:1px">FINDINGS</div></div>
    <div style="text-align:center"><div style="font-size:28px;font-weight:700;color:#ff8a8a;font-family:monospace">{agg['critical']}</div><div style="font-size:10px;color:#64748b;letter-spacing:1px">CRITICAL</div></div>
    <div style="text-align:center"><div style="font-size:28px;font-weight:700;color:#ffb84d;font-family:monospace">{agg['high']}</div><div style="font-size:10px;color:#64748b;letter-spacing:1px">HIGH</div></div>
  </div>
  <div style="background:#1e1b4b;border:1px solid #3730a3;border-radius:8px;padding:16px 20px;margin-bottom:16px">
    <h3 style="color:#a5b4fc;margin:0 0 8px;font-size:13px">⚡ Immediate Actions</h3>
    <ol style="color:#94a3b8;margin:0;padding-left:18px;font-size:12px;line-height:2">
      <li>Revoke <strong style="color:#e2e8f0">every exposed credential</strong> immediately — assume all compromised</li>
      <li>Rotate secrets and generate fresh keys for each affected service</li>
      <li>Audit service logs for unauthorized access since the first commit date</li>
      <li>Store secrets in environment variables or a secrets manager (Vault, AWS SM, Doppler)</li>
      <li>Add <code style="background:#0f172a;padding:1px 5px;border-radius:3px">.env</code> to <code style="background:#0f172a;padding:1px 5px;border-radius:3px">.gitignore</code></li>
      <li>Use <code style="background:#0f172a;padding:1px 5px;border-radius:3px">git filter-repo</code> to purge secrets from git history</li>
    </ol>
  </div>
  {rows_html}
  <p style="color:#334155;font-size:10px;text-align:center;margin-top:20px">
    GitHub Sentinel · Automated security scanning · Report for {recipient}
  </p>
</div></body></html>"""


# ── Email channel ──────────────────────────────────────────────────────────────
def send_email(results: list[dict], recipient: str, smtp_cfg: dict,
               job_id: str = "") -> tuple[bool, str]:
    if not results:
        return False, "No results to send."

    total   = sum(r.get("summary",{}).get("total_findings",0) for r in results)
    subject = f"[Sentinel] {total} secrets across {len(results)} repos — immediate action required"
    html    = build_html_report(results, recipient)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = smtp_cfg.get("user","sentinel@sentinel.io")
    msg["To"]      = recipient
    msg.attach(MIMEText(html, "html"))

    host = smtp_cfg.get("host","")
    if not host:
        log_alert(job_id, recipient, "email", subject, "preview", len(results), total)
        return True, html   # preview mode

    try:
        srv = smtplib.SMTP(host, int(smtp_cfg.get("port",587)), timeout=15)
        srv.ehlo()
        if smtp_cfg.get("tls", True): srv.starttls()
        user = smtp_cfg.get("user","")
        pw   = smtp_cfg.get("password","")
        if user and pw: srv.login(user, pw)
        srv.sendmail(user, recipient, msg.as_string())
        srv.quit()
        log_alert(job_id, recipient, "email", subject, "sent", len(results), total)
        return True, f"Alert sent to {recipient}"
    except Exception as e:
        log_alert(job_id, recipient, "email", subject, "error", len(results), total, str(e))
        return False, str(e)


# ── Webhook channel ────────────────────────────────────────────────────────────
def send_webhook(results: list[dict], webhook_url: str, job_id: str = "") -> tuple[bool, str]:
    if not results:
        return False, "No results."

    payload = {
        "event":       "sentinel.scan.complete",
        "job_id":      job_id,
        "total_repos": len(results),
        "total_findings": sum(r.get("summary",{}).get("total_findings",0) for r in results),
        "critical":    sum(r.get("summary",{}).get("severity_counts",{}).get("critical",0) for r in results),
        "repos": [
            {
                "full_name":    r.get("full_name",""),
                "risk_score":   r.get("summary",{}).get("risk_score",0),
                "total_findings": r.get("summary",{}).get("total_findings",0),
                "html_url":     r.get("repo_info",{}).get("html_url",""),
                "findings": [
                    {"type": f.get("type",""), "severity": f.get("severity",""),
                     "file": f.get("file_path","") or f.get("file",""),
                     "line": f.get("line_number") or f.get("line",0),
                     "fingerprint": f.get("fingerprint","")}
                    for f in r.get("findings",[])[:20]
                ]
            } for r in results
        ]
    }
    try:
        resp = requests.post(webhook_url, json=payload, timeout=15)
        if resp.status_code < 300:
            log_alert(job_id, webhook_url, "webhook", "scan.complete",
                      "sent", len(results), payload["total_findings"])
            return True, f"Webhook delivered ({resp.status_code})"
        else:
            return False, f"Webhook returned {resp.status_code}: {resp.text[:200]}"
    except Exception as e:
        return False, str(e)


# ── GitHub Issue channel ───────────────────────────────────────────────────────
def send_github_issues(results: list[dict], token: str, job_id: str = "") -> dict:
    created, failed = [], []
    for res in results:
        if res.get("summary",{}).get("total_findings",0) == 0:
            continue
        fn    = res.get("full_name","")
        parts = fn.split("/")
        if len(parts) != 2: continue
        owner, repo = parts

        findings = res.get("findings", [])
        summary_lines = "\n".join(
            f"- **{f['severity'].upper()}** `{f.get('type','')}` in `{f.get('file_path') or f.get('file','?')}:{f.get('line_number') or f.get('line','?')}`"
            for f in findings[:15]
        )
        total = res.get("summary",{}).get("total_findings",0)
        issue = create_security_issue(owner, repo, token, summary_lines, total)
        if issue:
            created.append({"repo": fn, "issue_url": issue.get("html_url","")})
            log_alert(job_id, fn, "github_issue",
                      f"Security: {total} secrets", "sent", 1, total)
        else:
            failed.append(fn)
    return {"created": created, "failed": failed}
