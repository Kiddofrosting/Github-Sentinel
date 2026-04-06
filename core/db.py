"""
SQLite persistence layer.
All jobs, findings, alert history, and scan diffs are stored here.
Thread-safe via WAL mode + check_same_thread=False with explicit locking.
"""
import sqlite3, threading, json, os, logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)

DB_PATH = os.environ.get("SENTINEL_DB", "sentinel.db")
_local  = threading.local()


def _conn() -> sqlite3.Connection:
    if not hasattr(_local, "conn") or _local.conn is None:
        c = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA foreign_keys=ON")
        c.row_factory = sqlite3.Row
        _local.conn = c
    return _local.conn


def init_db():
    c = _conn()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS jobs (
        id          TEXT PRIMARY KEY,
        created_at  TEXT NOT NULL,
        finished_at TEXT,
        status      TEXT NOT NULL DEFAULT 'running',
        total       INTEGER NOT NULL DEFAULT 0,
        completed   INTEGER NOT NULL DEFAULT 0,
        errored     INTEGER NOT NULL DEFAULT 0,
        token_hint  TEXT,
        meta        TEXT DEFAULT '{}'
    );

    CREATE TABLE IF NOT EXISTS repo_scans (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id      TEXT NOT NULL REFERENCES jobs(id),
        full_name   TEXT NOT NULL,
        owner       TEXT NOT NULL,
        repo        TEXT NOT NULL,
        status      TEXT NOT NULL DEFAULT 'queued',
        scanned_at  TEXT,
        files_scanned INTEGER DEFAULT 0,
        total_findings INTEGER DEFAULT 0,
        risk_score  INTEGER DEFAULT 0,
        repo_info   TEXT DEFAULT '{}',
        summary     TEXT DEFAULT '{}',
        error_msg   TEXT,
        UNIQUE(job_id, full_name)
    );

    CREATE TABLE IF NOT EXISTS findings (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id          TEXT NOT NULL,
        repo_full_name  TEXT NOT NULL,
        fingerprint     TEXT NOT NULL,
        type            TEXT NOT NULL,
        category        TEXT NOT NULL,
        severity        TEXT NOT NULL,
        description     TEXT,
        remediation     TEXT,
        docs_url        TEXT,
        file_path       TEXT,
        line_number     INTEGER,
        masked_value    TEXT,
        context_snippet TEXT,
        entropy         REAL,
        is_test_file    INTEGER DEFAULT 0,
        confidence      TEXT DEFAULT 'high',
        first_seen      TEXT,
        suppressed      INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS alert_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id      TEXT,
        sent_at     TEXT NOT NULL,
        recipient   TEXT NOT NULL,
        channel     TEXT NOT NULL DEFAULT 'email',
        subject     TEXT,
        status      TEXT NOT NULL DEFAULT 'sent',
        error_msg   TEXT,
        repo_count  INTEGER DEFAULT 0,
        finding_count INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS scan_diffs (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id_before   TEXT,
        job_id_after    TEXT NOT NULL,
        repo_full_name  TEXT NOT NULL,
        new_findings    INTEGER DEFAULT 0,
        fixed_findings  INTEGER DEFAULT 0,
        persisted_findings INTEGER DEFAULT 0,
        diff_json       TEXT DEFAULT '{}',
        computed_at     TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS suppressions (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        fingerprint TEXT NOT NULL UNIQUE,
        reason      TEXT,
        suppressed_at TEXT NOT NULL,
        suppressed_by TEXT DEFAULT 'user'
    );

    CREATE INDEX IF NOT EXISTS idx_findings_job   ON findings(job_id);
    CREATE INDEX IF NOT EXISTS idx_findings_repo  ON findings(repo_full_name);
    CREATE INDEX IF NOT EXISTS idx_findings_fp    ON findings(fingerprint);
    CREATE INDEX IF NOT EXISTS idx_repo_scans_job ON repo_scans(job_id);
    """)
    c.commit()
    log.info(f"DB initialised at {DB_PATH}")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Jobs ───────────────────────────────────────────────────────────────────────
def create_job(job_id: str, targets: list, token: str | None = None):
    c = _conn()
    hint = (token[:4] + "…") if token else None
    c.execute("INSERT INTO jobs(id,created_at,status,total,token_hint) VALUES(?,?,?,?,?)",
              (job_id, now_iso(), "running", len(targets), hint))
    for owner, repo in targets:
        c.execute("""INSERT OR IGNORE INTO repo_scans(job_id,full_name,owner,repo,status)
                     VALUES(?,?,?,?,?)""",
                  (job_id, f"{owner}/{repo}", owner, repo, "queued"))
    c.commit()


def update_job(job_id: str, **kwargs):
    allowed = {"status","completed","errored","finished_at","meta"}
    sets = ", ".join(f"{k}=?" for k in kwargs if k in allowed)
    vals = [v for k,v in kwargs.items() if k in allowed]
    if not sets: return
    _conn().execute(f"UPDATE jobs SET {sets} WHERE id=?", [*vals, job_id])
    _conn().commit()


def update_repo_scan(job_id: str, full_name: str, **kwargs):
    allowed = {"status","scanned_at","files_scanned","total_findings",
               "risk_score","repo_info","summary","error_msg"}
    sets = ", ".join(f"{k}=?" for k in kwargs if k in allowed)
    vals = [json.dumps(v) if isinstance(v, (dict,list)) else v
            for k,v in kwargs.items() if k in allowed]
    if not sets: return
    _conn().execute(
        f"UPDATE repo_scans SET {sets} WHERE job_id=? AND full_name=?",
        [*vals, job_id, full_name])
    _conn().commit()


def get_job(job_id: str) -> dict | None:
    row = _conn().execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    if not row: return None
    d = dict(row)
    repos = _conn().execute(
        "SELECT full_name,status,error_msg,total_findings,risk_score FROM repo_scans WHERE job_id=?",
        (job_id,)).fetchall()
    d["repos"] = {r["full_name"]: {"status":r["status"],"message":r["error_msg"] or r["status"],
                                    "findings":r["total_findings"],"risk":r["risk_score"]} for r in repos}
    return d


def get_all_jobs() -> list[dict]:
    rows = _conn().execute(
        "SELECT * FROM jobs ORDER BY created_at DESC LIMIT 50").fetchall()
    return [dict(r) for r in rows]


# ── Findings ───────────────────────────────────────────────────────────────────
def insert_findings(job_id: str, full_name: str, findings: list[dict]):
    if not findings: return
    c = _conn()
    suppressed_fps = {r[0] for r in c.execute(
        "SELECT fingerprint FROM suppressions").fetchall()}
    rows = []
    for f in findings:
        fp = f.get("fingerprint","")
        rows.append((
            job_id, full_name, fp,
            f.get("type",""), f.get("category",""), f.get("severity",""),
            f.get("description",""), f.get("remediation",""), f.get("docs",""),
            f.get("file",""), f.get("line",0), f.get("masked",""),
            f.get("context",""), f.get("entropy",0.0),
            1 if f.get("is_test_file") else 0,
            f.get("confidence","high"), now_iso(),
            1 if fp in suppressed_fps else 0
        ))
    c.executemany("""
        INSERT INTO findings(job_id,repo_full_name,fingerprint,type,category,severity,
            description,remediation,docs_url,file_path,line_number,masked_value,
            context_snippet,entropy,is_test_file,confidence,first_seen,suppressed)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, rows)
    c.commit()


def get_findings(job_id: str, repo: str | None = None,
                 min_severity: str | None = None,
                 include_suppressed: bool = False) -> list[dict]:
    q   = "SELECT * FROM findings WHERE job_id=?"
    args: list = [job_id]
    if repo:
        q += " AND repo_full_name=?"; args.append(repo)
    if not include_suppressed:
        q += " AND suppressed=0"
    if min_severity:
        sev_order = {"critical":0,"high":1,"medium":2,"low":3}
        cutoff = sev_order.get(min_severity, 3)
        q += f" AND severity IN ({','.join('?' for _ in [s for s,v in sev_order.items() if v<=cutoff])})"
        args.extend([s for s,v in sev_order.items() if v<=cutoff])
    q += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, entropy DESC"
    rows = _conn().execute(q, args).fetchall()
    return [dict(r) for r in rows]


def suppress_finding(fingerprint: str, reason: str = ""):
    c = _conn()
    c.execute("INSERT OR IGNORE INTO suppressions(fingerprint,reason,suppressed_at) VALUES(?,?,?)",
              (fingerprint, reason, now_iso()))
    c.execute("UPDATE findings SET suppressed=1 WHERE fingerprint=?", (fingerprint,))
    c.commit()


def get_repo_result(job_id: str, full_name: str) -> dict | None:
    row = _conn().execute(
        "SELECT * FROM repo_scans WHERE job_id=? AND full_name=?",
        (job_id, full_name)).fetchone()
    if not row: return None
    d = dict(row)
    d["repo_info"] = json.loads(d.get("repo_info") or "{}")
    d["summary"]   = json.loads(d.get("summary") or "{}")
    d["findings"]  = get_findings(job_id, full_name)
    return d


def get_all_repo_results(job_id: str) -> list[dict]:
    rows = _conn().execute(
        "SELECT full_name FROM repo_scans WHERE job_id=? ORDER BY risk_score DESC",
        (job_id,)).fetchall()
    results = []
    for row in rows:
        r = get_repo_result(job_id, row["full_name"])
        if r: results.append(r)
    return results


# ── Alert log ──────────────────────────────────────────────────────────────────
def log_alert(job_id: str, recipient: str, channel: str, subject: str,
              status: str, repo_count: int, finding_count: int, error: str = ""):
    _conn().execute("""
        INSERT INTO alert_log(job_id,sent_at,recipient,channel,subject,status,error_msg,repo_count,finding_count)
        VALUES(?,?,?,?,?,?,?,?,?)
    """, (job_id, now_iso(), recipient, channel, subject, status, error, repo_count, finding_count))
    _conn().commit()


def get_alert_log(job_id: str | None = None) -> list[dict]:
    if job_id:
        rows = _conn().execute(
            "SELECT * FROM alert_log WHERE job_id=? ORDER BY sent_at DESC", (job_id,)).fetchall()
    else:
        rows = _conn().execute(
            "SELECT * FROM alert_log ORDER BY sent_at DESC LIMIT 100").fetchall()
    return [dict(r) for r in rows]


# ── Scan diff ──────────────────────────────────────────────────────────────────
def compute_diff(job_before: str | None, job_after: str, repo: str) -> dict:
    """Compare findings between two jobs for the same repo."""
    after_fps = {r["fingerprint"] for r in get_findings(job_after, repo)}
    before_fps = {r["fingerprint"] for r in get_findings(job_before, repo)} if job_before else set()

    new_fps       = after_fps - before_fps
    fixed_fps     = before_fps - after_fps
    persisted_fps = after_fps & before_fps

    diff = {
        "new":       list(new_fps),
        "fixed":     list(fixed_fps),
        "persisted": list(persisted_fps),
    }
    _conn().execute("""
        INSERT INTO scan_diffs(job_id_before,job_id_after,repo_full_name,
            new_findings,fixed_findings,persisted_findings,diff_json,computed_at)
        VALUES(?,?,?,?,?,?,?,?)
    """, (job_before, job_after, repo, len(new_fps), len(fixed_fps),
          len(persisted_fps), json.dumps(diff), now_iso()))
    _conn().commit()
    return diff


def get_previous_job_for_repo(current_job: str, repo: str) -> str | None:
    row = _conn().execute("""
        SELECT rs.job_id FROM repo_scans rs
        JOIN jobs j ON rs.job_id = j.id
        WHERE rs.full_name=? AND rs.job_id != ? AND j.status='complete'
        ORDER BY j.finished_at DESC LIMIT 1
    """, (repo, current_job)).fetchone()
    return row[0] if row else None


# ── Stats ──────────────────────────────────────────────────────────────────────
def get_global_stats() -> dict:
    c = _conn()
    total_jobs     = c.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
    total_repos    = c.execute("SELECT COUNT(*) FROM repo_scans WHERE status='complete'").fetchone()[0]
    total_findings = c.execute("SELECT COUNT(*) FROM findings WHERE suppressed=0").fetchone()[0]
    critical       = c.execute("SELECT COUNT(*) FROM findings WHERE severity='critical' AND suppressed=0").fetchone()[0]
    alerts_sent    = c.execute("SELECT COUNT(*) FROM alert_log WHERE status='sent'").fetchone()[0]
    top_types_rows = c.execute("""
        SELECT type, COUNT(*) as cnt FROM findings WHERE suppressed=0
        GROUP BY type ORDER BY cnt DESC LIMIT 5
    """).fetchall()
    return {
        "total_jobs": total_jobs,
        "total_repos": total_repos,
        "total_findings": total_findings,
        "critical_findings": critical,
        "alerts_sent": alerts_sent,
        "top_secret_types": [{"type": r[0], "count": r[1]} for r in top_types_rows],
    }
