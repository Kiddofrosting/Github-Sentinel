"""GitHub API — v3. Adds: commit history scanning, owner contact lookup, search API."""
import requests, re, time, base64, logging

log = logging.getLogger(__name__)

SKIP_DIRS  = {"node_modules",".git","vendor","dist","build","__pycache__",
              ".venv","venv","coverage","target","bin","obj","pkg",".next","out"}
SKIP_EXTS  = {"png","jpg","jpeg","gif","ico","svg","webp","woff","woff2","ttf",
              "eot","mp4","mp3","wav","ogg","zip","tar","gz","bz2","xz","pdf",
              "doc","docx","xls","xlsx","ppt","pptx","lock","sum","resolved","map",
              "min.js","min.css","bundle.js"}
MAX_FILE_BYTES = 400_000


def _headers(token: str | None) -> dict:
    h = {"Accept": "application/vnd.github.v3+json",
         "User-Agent": "Sentinel-v3/1.0 (security-scanner)"}
    if token:
        h["Authorization"] = f"token {token}"
    return h


def _get(url: str, token: str | None, retries=3, timeout=15) -> requests.Response | None:
    for attempt in range(retries):
        try:
            r = requests.get(url, headers=_headers(token), timeout=timeout)
            if r.status_code == 403:
                remaining = r.headers.get("X-RateLimit-Remaining","1")
                if remaining == "0":
                    reset = int(r.headers.get("X-RateLimit-Reset", time.time() + 65))
                    wait  = max(reset - time.time(), 1)
                    log.warning(f"Rate limited — sleeping {wait:.0f}s")
                    time.sleep(min(wait, 70))
                    continue
            if r.status_code == 202:
                time.sleep(2); continue
            return r
        except requests.exceptions.RequestException as e:
            if attempt < retries - 1:
                time.sleep(1.5 * (attempt + 1))
            else:
                log.error(f"Request failed {url}: {e}")
    return None


def get_user_info(handle: str, token: str | None) -> dict | None:
    r = _get(f"https://api.github.com/users/{handle}", token)
    return r.json() if r and r.status_code == 200 else None


def get_org_repos(org: str, token: str | None, max_repos=100) -> list[dict]:
    repos, page = [], 1
    while len(repos) < max_repos:
        r = _get(f"https://api.github.com/orgs/{org}/repos?per_page=100&page={page}&type=public", token)
        if not r or r.status_code != 200: break
        batch = r.json()
        if not batch: break
        repos.extend(batch); page += 1
    return repos[:max_repos]


def get_user_repos(username: str, token: str | None, max_repos=100) -> list[dict]:
    repos, page = [], 1
    while len(repos) < max_repos:
        r = _get(f"https://api.github.com/users/{username}/repos?per_page=100&page={page}&sort=pushed", token)
        if not r or r.status_code != 200: break
        batch = r.json()
        if not batch: break
        repos.extend(batch); page += 1
    return repos[:max_repos]


def get_repo_info(owner: str, repo: str, token: str | None) -> dict | None:
    r = _get(f"https://api.github.com/repos/{owner}/{repo}", token)
    return r.json() if r and r.status_code == 200 else None


def get_repo_tree(owner: str, repo: str, branch: str, token: str | None) -> tuple[list[dict], bool]:
    """Single-request flat file tree via Trees API. Always returns (files, truncated)."""
    r = _get(f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1", token)
    if not r or r.status_code != 200: return [], False
    data  = r.json()
    files = []
    truncated = data.get("truncated", False)
    for item in data.get("tree", []):
        if item.get("type") != "blob": continue
        path: str = item.get("path","")
        parts = path.split("/")
        if any(p in SKIP_DIRS for p in parts): continue
        fname = parts[-1]
        ext   = fname.rsplit(".",1)[-1].lower() if "." in fname else ""
        if ext in SKIP_EXTS: continue
        if fname.endswith((".min.js",".min.css",".bundle.js")): continue
        size = item.get("size", 0)
        if size > MAX_FILE_BYTES or size == 0: continue
        files.append({"path": path, "sha": item.get("sha",""), "size": size})
    return files, truncated


def fetch_blob(owner: str, repo: str, sha: str, token: str | None) -> str | None:
    r = _get(f"https://api.github.com/repos/{owner}/{repo}/git/blobs/{sha}", token)
    if not r or r.status_code != 200: return None
    data = r.json()
    try:
        if data.get("encoding") == "base64":
            return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        return data.get("content","")
    except Exception:
        return None


# ── Commit history scanning ────────────────────────────────────────────────────
def get_recent_commits(owner: str, repo: str, token: str | None, max_commits=50) -> list[dict]:
    r = _get(f"https://api.github.com/repos/{owner}/{repo}/commits?per_page={max_commits}", token)
    if not r or r.status_code != 200: return []
    return r.json()


def get_commit_diff(owner: str, repo: str, sha: str, token: str | None) -> str | None:
    """Fetch raw unified diff for a commit."""
    r = requests.get(
        f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}",
        headers={**_headers(token), "Accept": "application/vnd.github.v3.diff"},
        timeout=15
    )
    if r and r.status_code == 200:
        return r.text
    return None


# ── Owner contact lookup ───────────────────────────────────────────────────────
def get_owner_email(owner: str, repo: str, token: str | None) -> str | None:
    """
    Try multiple strategies to find a contact email:
    1. User profile (public email)
    2. Most recent commit author email (if not noreply)
    """
    # Strategy 1: public profile
    info = get_user_info(owner, token)
    if info and info.get("email"):
        return info["email"]

    # Strategy 2: commit author email
    r = _get(f"https://api.github.com/repos/{owner}/{repo}/commits?per_page=5", token)
    if r and r.status_code == 200:
        for commit in r.json():
            email = commit.get("commit",{}).get("author",{}).get("email","")
            if email and "noreply" not in email and "@" in email:
                return email
    return None


# ── Rate limit ─────────────────────────────────────────────────────────────────
def get_rate_limit(token: str | None) -> dict:
    r = _get("https://api.github.com/rate_limit", token)
    if r and r.status_code == 200:
        return r.json().get("resources",{}).get("core",{})
    return {}


# ── GitHub Issues / Security Advisories ───────────────────────────────────────
def create_security_issue(owner: str, repo: str, token: str | None,
                           findings_summary: str, total: int) -> dict | None:
    """Open a private GitHub Issue reporting the findings."""
    if not token: return None
    title = f"[Security] {total} exposed secret(s) detected by GitHub Sentinel"
    body  = f"""## 🔐 Security Alert — Exposed Credentials Detected

GitHub Sentinel has detected **{total} exposed secret(s)** in this repository.

### Summary
{findings_summary}

### Immediate Actions
1. **Revoke every listed credential immediately** — assume all are compromised
2. Rotate and generate fresh keys/tokens for each service
3. Audit service logs for unauthorized access
4. Move secrets to environment variables or a secrets manager (Vault, AWS Secrets Manager, Doppler)
5. Add `.env` to `.gitignore` and install [git-secrets](https://github.com/awslabs/git-secrets) pre-commit hooks
6. Run `git filter-repo` to purge secrets from git history — deletion from HEAD is not enough

---
*Sent by [GitHub Sentinel](https://github.com) — automated security scanning to promote secure coding practices.*
"""
    r = requests.post(
        f"https://api.github.com/repos/{owner}/{repo}/issues",
        headers={**_headers(token), "Content-Type": "application/json"},
        json={"title": title, "body": body, "labels": ["security"]},
        timeout=15
    )
    if r and r.status_code == 201:
        return r.json()
    return None


def parse_repo_input(raw: str) -> tuple[str,str] | None:
    raw = raw.strip().rstrip("/")
    for pat in [r"github\.com/([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+)",
                r"^([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+)$"]:
        m = re.search(pat, raw)
        if m: return m.group(1), m.group(2).removesuffix(".git")
    return None
