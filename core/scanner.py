"""
Scanner engine — v3.
- SQLite-backed persistence
- Deduplication by fingerprint
- Entropy + placeholder gating
- Commit history scanning
- Job cancellation
- Scan diff computation
- Per-repo owner email lookup
"""
import re, time, threading, logging, uuid
from concurrent.futures import ThreadPoolExecutor, as_completed, Future

from core.patterns import scan_content, calculate_risk_score, SECRET_PATTERNS
from core.github import (
    get_repo_info, get_repo_tree, fetch_blob,
    get_user_repos, get_org_repos, get_user_info,
    parse_repo_input, get_rate_limit,
    get_recent_commits, get_commit_diff, get_owner_email,
)
from core.db import (
    create_job as db_create_job, update_job, update_repo_scan,
    get_job, get_all_jobs, insert_findings, get_findings,
    get_repo_result, get_all_repo_results,
    compute_diff, get_previous_job_for_repo, now_iso,
)

log = logging.getLogger(__name__)

MAX_WORKERS        = 6
MAX_FILES_PER_REPO = 500
MAX_COMMITS_SCAN   = 30   # how many commits to scan for history mode

# Cancel signals: job_id → threading.Event
_cancel_events: dict[str, threading.Event] = {}
_cancel_lock = threading.Lock()


# ── Helpers ────────────────────────────────────────────────────────────────────
def _cancelled(job_id: str) -> bool:
    with _cancel_lock:
        ev = _cancel_events.get(job_id)
    return ev is not None and ev.is_set()


def _set_repo_msg(job_id: str, full_name: str, status: str, msg: str):
    update_repo_scan(job_id, full_name, status=status)
    log.info(f"[{job_id}] {full_name}: {msg}")


# ── Per-repo HEAD scan ─────────────────────────────────────────────────────────
def _scan_repo_head(owner: str, repo: str, token: str | None,
                    job_id: str, scan_history: bool) -> dict:
    full_name = f"{owner}/{repo}"

    if _cancelled(job_id):
        _set_repo_msg(job_id, full_name, "cancelled", "Job cancelled")
        update_repo_scan(job_id, full_name, status="cancelled", error_msg="cancelled")
        return {"full_name": full_name, "status": "cancelled", "findings": []}

    _set_repo_msg(job_id, full_name, "scanning", "Fetching repo info…")
    info = get_repo_info(owner, repo, token)
    if not info:
        update_repo_scan(job_id, full_name, status="error",
                         error_msg="Not found or inaccessible")
        return {"full_name": full_name, "status": "error"}

    branch    = info.get("default_branch", "main")
    owner_email = get_owner_email(owner, repo, token)

    # ── HEAD tree scan ──
    _set_repo_msg(job_id, full_name, "scanning", f"Discovering files on '{branch}'…")
    files, truncated = get_repo_tree(owner, repo, branch, token)
    files    = files[:MAX_FILES_PER_REPO]
    total    = len(files)

    all_findings: list[dict] = []
    scanned = 0

    for fobj in files:
        if _cancelled(job_id): break
        update_repo_scan(job_id, full_name, status="scanning")
        content = fetch_blob(owner, repo, fobj["sha"], token)
        if content:
            found = scan_content(content, fobj["path"], job_id, full_name)
            all_findings.extend(found)
        scanned += 1
        time.sleep(0.04)

    # ── Commit history scan ──
    if scan_history and not _cancelled(job_id):
        _set_repo_msg(job_id, full_name, "scanning", "Scanning commit history…")
        commits = get_recent_commits(owner, repo, token, MAX_COMMITS_SCAN)
        for commit in commits[:MAX_COMMITS_SCAN]:
            if _cancelled(job_id): break
            sha  = commit.get("sha","")
            diff = get_commit_diff(owner, repo, sha, token)
            if diff:
                hist_findings = scan_content(diff, f"[history:{sha[:7]}]", job_id, full_name)
                # mark them as coming from history, deduplicate by fingerprint
                existing_fps = {f["fingerprint"] for f in all_findings}
                for hf in hist_findings:
                    hf["from_history"] = True
                    if hf["fingerprint"] not in existing_fps:
                        all_findings.append(hf)
                        existing_fps.add(hf["fingerprint"])
            time.sleep(0.1)

    # Deduplicate within this repo by fingerprint
    seen_fps: set = set()
    deduped: list = []
    for f in all_findings:
        if f["fingerprint"] not in seen_fps:
            deduped.append(f)
            seen_fps.add(f["fingerprint"])

    # Severity aggregation
    sev_counts = {"critical":0,"high":0,"medium":0,"low":0}
    for f in deduped:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"],0) + 1

    risk = calculate_risk_score(sev_counts)

    repo_info_payload = {
        "name":          info.get("full_name", full_name),
        "description":   info.get("description") or "",
        "html_url":      info.get("html_url",""),
        "stars":         info.get("stargazers_count",0),
        "forks":         info.get("forks_count",0),
        "language":      info.get("language") or "Unknown",
        "private":       info.get("private", False),
        "default_branch": branch,
        "owner_login":   info.get("owner",{}).get("login",""),
        "owner_avatar":  info.get("owner",{}).get("avatar_url",""),
        "owner_type":    info.get("owner",{}).get("type","User"),
        "owner_email":   owner_email,
        "size_kb":       info.get("size",0),
        "truncated_tree": truncated,
    }

    summary_payload = {
        "files_scanned":   scanned,
        "total_findings":  len(deduped),
        "severity_counts": sev_counts,
        "risk_score":      risk,
        "history_scanned": scan_history,
    }

    update_repo_scan(
        job_id, full_name,
        status="complete",
        scanned_at=now_iso(),
        files_scanned=scanned,
        total_findings=len(deduped),
        risk_score=risk,
        repo_info=repo_info_payload,
        summary=summary_payload,
    )

    insert_findings(job_id, full_name, deduped)

    # Compute diff vs last scan
    prev_job = get_previous_job_for_repo(job_id, full_name)
    diff_result = compute_diff(prev_job, job_id, full_name) if prev_job else None

    return {
        "full_name":  full_name,
        "status":     "complete",
        "repo_info":  repo_info_payload,
        "summary":    summary_payload,
        "findings":   deduped,
        "diff":       diff_result,
    }


# ── Job runner ─────────────────────────────────────────────────────────────────
def _run_job(job_id: str, targets: list[tuple[str,str]],
             token: str | None, scan_history: bool):
    futures: dict[Future, tuple[str,str]] = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        for owner, repo in targets:
            if _cancelled(job_id): break
            f = pool.submit(_scan_repo_head, owner, repo, token, job_id, scan_history)
            futures[f] = (owner, repo)

        completed = 0
        errored   = 0
        for fut in as_completed(futures):
            owner, repo = futures[fut]
            try:
                res = fut.result()
                if res.get("status") == "error":
                    errored += 1
                else:
                    completed += 1
            except Exception as exc:
                log.exception(f"[{job_id}] Unhandled error {owner}/{repo}: {exc}")
                update_repo_scan(job_id, f"{owner}/{repo}", status="error",
                                 error_msg=str(exc)[:200])
                errored += 1
            update_job(job_id, completed=completed, errored=errored)

    status = "cancelled" if _cancelled(job_id) else "complete"
    update_job(job_id, status=status, finished_at=now_iso(),
               completed=completed, errored=errored)
    log.info(f"[{job_id}] Job {status}: {completed} ok, {errored} errors")


# ── Public API ─────────────────────────────────────────────────────────────────
def create_job(targets: list[tuple[str,str]], token: str | None,
               scan_history: bool = False) -> str:
    job_id = uuid.uuid4().hex[:12]
    db_create_job(job_id, targets, token)
    cancel_ev = threading.Event()
    with _cancel_lock:
        _cancel_events[job_id] = cancel_ev
    t = threading.Thread(target=_run_job, args=(job_id, targets, token, scan_history), daemon=True)
    t.start()
    return job_id


def cancel_job(job_id: str) -> bool:
    with _cancel_lock:
        ev = _cancel_events.get(job_id)
    if ev:
        ev.set()
        update_job(job_id, status="cancelling")
        return True
    return False


def discover_repos(handle: str, token: str | None, max_repos: int = 50) -> list[tuple[str,str]]:
    info = get_user_info(handle, token)
    if not info: return []
    if info.get("type") == "Organization":
        repos = get_org_repos(handle, token, max_repos)
    else:
        repos = get_user_repos(handle, token, max_repos)
    return [(r["owner"]["login"], r["name"]) for r in repos if not r.get("archived")]
