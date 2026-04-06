"""
Secret detection patterns — v3.
Each pattern now includes:
  - min_entropy:   Shannon entropy floor (0 = no check). Rejects placeholders.
  - min_length:    Minimum matched string length filter.
  - allow_test:    If False, downgrade confidence on test/fixture files.
  - false_positive_hints: substrings that strongly indicate a placeholder.
"""
import math, re

# Files/paths that are almost certainly test fixtures or examples
TEST_PATH_PATTERNS = re.compile(
    r"(test|spec|fixture|mock|fake|example|sample|demo|stub|__tests__|\.test\.|\.spec\.|_test\.|test_)",
    re.IGNORECASE,
)

PLACEHOLDER_HINTS = {
    "changeme","placeholder","example","your_","<your","yourkey",
    "insert_","replace_","todo","fixme","xxxxxxxxxx","0000000000",
    "aaaaaaaaa","1234567890","abcdefghij","test_secret","fake_key",
    "dummy","sample","enter_your","add_your","put_your","my_secret",
    "secret_here","key_here","token_here",
}

def is_placeholder(value: str) -> bool:
    v = value.lower()
    return any(h in v for h in PLACEHOLDER_HINTS)

def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f/n) * math.log2(f/n) for f in freq.values())

def is_test_file(path: str) -> bool:
    return bool(TEST_PATH_PATTERNS.search(path))


SECRET_PATTERNS = {
    # ── Cloud ──────────────────────────────────────────────────────────────────
    "AWS Access Key ID": {
        "pattern": r"(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])",
        "severity": "critical", "category": "Cloud",
        "min_entropy": 3.0, "min_length": 20, "allow_test": False,
        "description": "AWS Access Key ID — programmatic access to AWS services.",
        "remediation": "Rotate in AWS IAM Console immediately. Audit CloudTrail for misuse.",
        "docs": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
    },
    "AWS Secret Access Key": {
        "pattern": r"(?i)aws[_\-\s]*secret[_\-\s]*(?:access[_\-\s]*)?key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "severity": "critical", "category": "Cloud",
        "min_entropy": 4.0, "min_length": 40, "allow_test": False,
        "description": "AWS Secret Access Key — paired with Access Key ID.",
        "remediation": "Rotate in AWS IAM. Audit all regions for resource misuse.",
        "docs": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
    },
    "GCP Service Account Key": {
        "pattern": r'"type"\s*:\s*"service_account"',
        "severity": "critical", "category": "Cloud",
        "min_entropy": 0, "min_length": 0, "allow_test": False,
        "description": "GCP Service Account JSON key embedded in source.",
        "remediation": "Delete key in GCP IAM. Store in Secret Manager.",
        "docs": "https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys"
    },
    "Azure Storage Connection String": {
        "pattern": r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{60,}",
        "severity": "critical", "category": "Cloud",
        "min_entropy": 4.5, "min_length": 80, "allow_test": False,
        "description": "Azure Storage Account connection string with full access key.",
        "remediation": "Rotate storage keys in Azure Portal > Storage Account > Access Keys.",
        "docs": "https://docs.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage"
    },
    "DigitalOcean Token": {
        "pattern": r"dop_v1_[a-f0-9]{64}",
        "severity": "critical", "category": "Cloud",
        "min_entropy": 3.8, "min_length": 71, "allow_test": False,
        "description": "DigitalOcean Personal Access Token — full API access.",
        "remediation": "Revoke in DigitalOcean Control Panel > API > Tokens.",
        "docs": "https://docs.digitalocean.com/reference/api/create-personal-access-token/"
    },
    "Heroku API Key": {
        "pattern": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "severity": "high", "category": "Cloud",
        "min_entropy": 3.5, "min_length": 36, "allow_test": False,
        "description": "Heroku API Key (UUID format).",
        "remediation": "Revoke in Heroku Account Settings > API Key > Regenerate.",
        "docs": "https://devcenter.heroku.com/articles/authentication"
    },

    # ── DevOps & SCM ───────────────────────────────────────────────────────────
    "GitHub Personal Access Token": {
        "pattern": r"ghp_[A-Za-z0-9_]{36,255}",
        "severity": "critical", "category": "DevOps",
        "min_entropy": 4.0, "min_length": 40, "allow_test": False,
        "description": "GitHub Classic PAT — read/write repos and more.",
        "remediation": "Revoke at github.com/settings/tokens immediately.",
        "docs": "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure"
    },
    "GitHub OAuth Token": {
        "pattern": r"gho_[A-Za-z0-9_]{36,255}",
        "severity": "critical", "category": "DevOps",
        "min_entropy": 4.0, "min_length": 40, "allow_test": False,
        "description": "GitHub OAuth App Token.",
        "remediation": "Revoke at github.com/settings/applications.",
        "docs": "https://docs.github.com/en/developers/apps/building-oauth-apps"
    },
    "GitHub Actions Token": {
        "pattern": r"ghs_[A-Za-z0-9_]{36,255}",
        "severity": "critical", "category": "DevOps",
        "min_entropy": 4.0, "min_length": 40, "allow_test": False,
        "description": "GitHub Actions token — short-lived but still dangerous in logs.",
        "remediation": "Rotate via repository secrets and audit workflow logs.",
        "docs": "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"
    },
    "GitHub Fine-Grained Token": {
        "pattern": r"github_pat_[A-Za-z0-9_]{82}",
        "severity": "critical", "category": "DevOps",
        "min_entropy": 4.0, "min_length": 93, "allow_test": False,
        "description": "GitHub Fine-Grained Personal Access Token.",
        "remediation": "Revoke at github.com/settings/personal-access-tokens.",
        "docs": "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure"
    },
    "GitLab Token": {
        "pattern": r"glpat-[A-Za-z0-9\-_]{20}",
        "severity": "critical", "category": "DevOps",
        "min_entropy": 3.8, "min_length": 26, "allow_test": False,
        "description": "GitLab Personal Access Token.",
        "remediation": "Revoke in GitLab > User Settings > Access Tokens.",
        "docs": "https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html"
    },
    "NPM Access Token": {
        "pattern": r"npm_[A-Za-z0-9]{36}",
        "severity": "high", "category": "DevOps",
        "min_entropy": 3.8, "min_length": 40, "allow_test": False,
        "description": "NPM Automation/Publish access token.",
        "remediation": "Revoke at npmjs.com/settings/<user>/tokens.",
        "docs": "https://docs.npmjs.com/about-access-tokens"
    },

    # ── Payments ───────────────────────────────────────────────────────────────
    "Stripe Secret Key": {
        "pattern": r"sk_(live|test)_[0-9a-zA-Z]{24,}",
        "severity": "critical", "category": "Payments",
        "min_entropy": 4.0, "min_length": 32, "allow_test": False,
        "description": "Stripe Secret Key — can charge cards, refund, access all customer data.",
        "remediation": "Roll key immediately in Stripe Dashboard > Developers > API Keys.",
        "docs": "https://stripe.com/docs/keys"
    },
    "Stripe Restricted Key": {
        "pattern": r"rk_(live|test)_[0-9a-zA-Z]{24,}",
        "severity": "high", "category": "Payments",
        "min_entropy": 4.0, "min_length": 32, "allow_test": False,
        "description": "Stripe Restricted API Key.",
        "remediation": "Roll key in Stripe Dashboard > Developers > API Keys.",
        "docs": "https://stripe.com/docs/keys"
    },
    "PayPal Client Secret": {
        "pattern": r"(?i)paypal.{0,30}(?:client_secret|secret)\s*[=:]\s*['\"]([A-Za-z0-9\-_]{20,})['\"]",
        "severity": "critical", "category": "Payments",
        "min_entropy": 3.8, "min_length": 20, "allow_test": False,
        "description": "PayPal REST API Client Secret.",
        "remediation": "Regenerate in PayPal Developer Dashboard > My Apps.",
        "docs": "https://developer.paypal.com/api/rest/"
    },
    "Square Access Token": {
        "pattern": r"sq0atp-[A-Za-z0-9\-_]{22}",
        "severity": "critical", "category": "Payments",
        "min_entropy": 3.8, "min_length": 29, "allow_test": False,
        "description": "Square Production Access Token.",
        "remediation": "Revoke in Square Developer Dashboard > Applications.",
        "docs": "https://developer.squareup.com/docs/build-basics/access-tokens"
    },

    # ── Communication ──────────────────────────────────────────────────────────
    "Twilio Auth Token": {
        "pattern": r"(?i)twilio.{0,40}['\"]([a-f0-9]{32})['\"]",
        "severity": "high", "category": "Communication",
        "min_entropy": 3.8, "min_length": 32, "allow_test": False,
        "description": "Twilio Auth Token — can send SMS/calls as your account.",
        "remediation": "Regenerate Auth Token in Twilio Console > Settings.",
        "docs": "https://www.twilio.com/docs/iam/access-tokens"
    },
    "SendGrid API Key": {
        "pattern": r"SG\.[A-Za-z0-9\-._]{22}\.[A-Za-z0-9\-._]{43}",
        "severity": "high", "category": "Communication",
        "min_entropy": 4.2, "min_length": 69, "allow_test": False,
        "description": "SendGrid API Key — can send email as your domain.",
        "remediation": "Delete and recreate key in SendGrid Settings > API Keys.",
        "docs": "https://docs.sendgrid.com/ui/account-and-settings/api-keys"
    },
    "Mailgun API Key": {
        "pattern": r"key-[0-9a-zA-Z]{32}",
        "severity": "high", "category": "Communication",
        "min_entropy": 3.8, "min_length": 36, "allow_test": False,
        "description": "Mailgun Private API Key.",
        "remediation": "Regenerate in Mailgun Dashboard > Settings > API Keys.",
        "docs": "https://documentation.mailgun.com/en/latest/api-intro.html"
    },
    "Slack Bot Token": {
        "pattern": r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}",
        "severity": "high", "category": "Communication",
        "min_entropy": 4.0, "min_length": 50, "allow_test": False,
        "description": "Slack Bot Token — messages, channel access.",
        "remediation": "Revoke in Slack API > Your Apps > OAuth & Permissions.",
        "docs": "https://api.slack.com/authentication/token-types"
    },
    "Slack Webhook URL": {
        "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,10}/B[A-Z0-9]{8,10}/[A-Za-z0-9]{24}",
        "severity": "medium", "category": "Communication",
        "min_entropy": 0, "min_length": 0, "allow_test": True,
        "description": "Slack Incoming Webhook — can post to a channel.",
        "remediation": "Revoke webhook in Slack App > Incoming Webhooks.",
        "docs": "https://api.slack.com/messaging/webhooks"
    },
    "Discord Bot Token": {
        "pattern": r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}",
        "severity": "high", "category": "Communication",
        "min_entropy": 4.0, "min_length": 59, "allow_test": False,
        "description": "Discord Bot Token — full bot account control.",
        "remediation": "Regenerate in Discord Developer Portal > Applications > Bot.",
        "docs": "https://discord.com/developers/docs/topics/oauth2"
    },
    "Telegram Bot Token": {
        "pattern": r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}",
        "severity": "high", "category": "Communication",
        "min_entropy": 3.8, "min_length": 44, "allow_test": False,
        "description": "Telegram Bot API Token.",
        "remediation": "Revoke via @BotFather with /revoke.",
        "docs": "https://core.telegram.org/bots/api"
    },

    # ── Google / Firebase ──────────────────────────────────────────────────────
    "Google API Key": {
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": "high", "category": "Google",
        "min_entropy": 3.5, "min_length": 39, "allow_test": False,
        "description": "Google API Key (Maps, YouTube, Firebase, etc.).",
        "remediation": "Restrict or delete key in Google Cloud Console > Credentials.",
        "docs": "https://cloud.google.com/docs/authentication/api-keys"
    },
    "Firebase Server Key": {
        "pattern": r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}",
        "severity": "high", "category": "Google",
        "min_entropy": 4.2, "min_length": 150, "allow_test": False,
        "description": "Firebase Cloud Messaging Server Key.",
        "remediation": "Revoke in Firebase Console > Project Settings > Cloud Messaging.",
        "docs": "https://firebase.google.com/docs/cloud-messaging/auth-server"
    },

    # ── Cryptographic Keys ─────────────────────────────────────────────────────
    "RSA Private Key": {
        "pattern": r"-----BEGIN (RSA )?PRIVATE KEY-----",
        "severity": "critical", "category": "Cryptography",
        "min_entropy": 0, "min_length": 0, "allow_test": False,
        "description": "RSA Private Key — decrypts data, impersonates TLS servers.",
        "remediation": "Revoke all certs. Generate new keypair. Use a vault.",
        "docs": "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"
    },
    "EC Private Key": {
        "pattern": r"-----BEGIN EC PRIVATE KEY-----",
        "severity": "critical", "category": "Cryptography",
        "min_entropy": 0, "min_length": 0, "allow_test": False,
        "description": "Elliptic Curve Private Key.",
        "remediation": "Revoke associated certs and generate new keypair.",
        "docs": "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"
    },
    "OpenSSH Private Key": {
        "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "severity": "critical", "category": "Cryptography",
        "min_entropy": 0, "min_length": 0, "allow_test": False,
        "description": "OpenSSH Private Key — SSH server access.",
        "remediation": "Remove from all authorized_keys. Generate new keypair.",
        "docs": "https://www.openssh.com/manual.html"
    },
    "PGP Private Key": {
        "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "severity": "critical", "category": "Cryptography",
        "min_entropy": 0, "min_length": 0, "allow_test": False,
        "description": "PGP/GPG Private Key Block.",
        "remediation": "Revoke on keyserver. Generate new keypair.",
        "docs": "https://gnupg.org/documentation/"
    },

    # ── Databases ──────────────────────────────────────────────────────────────
    "Database Connection String": {
        "pattern": r"(postgres|postgresql|mysql|mongodb(\+srv)?|redis|mssql|mariadb)://[^\s'\"]{3,}:[^\s'\"]{3,}@[^\s'\"]+",
        "severity": "critical", "category": "Database",
        "min_entropy": 3.0, "min_length": 20, "allow_test": False,
        "description": "Database connection string with embedded credentials.",
        "remediation": "Rotate DB credentials. Restrict IP access. Use secrets manager.",
        "docs": "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html"
    },

    # ── Auth & Identity ────────────────────────────────────────────────────────
    "JWT Secret": {
        "pattern": r"(?i)jwt[_\-]?secret\s*[=:]\s*['\"]([A-Za-z0-9+/=_\-]{16,})['\"]",
        "severity": "high", "category": "Auth",
        "min_entropy": 3.5, "min_length": 16, "allow_test": False,
        "description": "JWT Signing Secret — can forge authentication tokens.",
        "remediation": "Rotate the secret and invalidate all existing JWTs.",
        "docs": "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"
    },
    "Auth0 Client Secret": {
        "pattern": r"(?i)auth0.{0,30}(?:client_secret)\s*[=:]\s*['\"]([A-Za-z0-9_\-]{40,})['\"]",
        "severity": "high", "category": "Auth",
        "min_entropy": 4.0, "min_length": 40, "allow_test": False,
        "description": "Auth0 Client Secret.",
        "remediation": "Rotate in Auth0 Dashboard > Applications > Settings.",
        "docs": "https://auth0.com/docs/get-started/applications"
    },

    # ── Monitoring ─────────────────────────────────────────────────────────────
    "Sentry DSN": {
        "pattern": r"https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+",
        "severity": "low", "category": "Monitoring",
        "min_entropy": 0, "min_length": 0, "allow_test": True,
        "description": "Sentry DSN — can submit error events.",
        "remediation": "Rotate in Sentry > Settings > Projects > Client Keys.",
        "docs": "https://docs.sentry.io/product/sentry-basics/dsn-explainer/"
    },
    "Datadog API Key": {
        "pattern": r"(?i)(?:datadog|dd)[_\-]?(?:api[_\-]?)?key\s*[=:]\s*['\"]([a-f0-9]{32})['\"]",
        "severity": "medium", "category": "Monitoring",
        "min_entropy": 3.8, "min_length": 32, "allow_test": False,
        "description": "Datadog API Key.",
        "remediation": "Revoke in Datadog > Organization Settings > API Keys.",
        "docs": "https://docs.datadoghq.com/account_management/api-app-keys/"
    },

    # ── Infrastructure ─────────────────────────────────────────────────────────
    "Cloudflare API Token": {
        "pattern": r"(?i)cloudflare.{0,30}['\"]([A-Za-z0-9_\-]{40})['\"]",
        "severity": "high", "category": "Infrastructure",
        "min_entropy": 4.0, "min_length": 40, "allow_test": False,
        "description": "Cloudflare API Token — DNS, firewall rules, WAF.",
        "remediation": "Rotate in Cloudflare Dashboard > My Profile > API Tokens.",
        "docs": "https://developers.cloudflare.com/fundamentals/api/"
    },
    "Cloudinary URL": {
        "pattern": r"cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[A-Za-z0-9_\-]+",
        "severity": "high", "category": "Infrastructure",
        "min_entropy": 3.5, "min_length": 20, "allow_test": False,
        "description": "Cloudinary config URL with API secret.",
        "remediation": "Reset API secret in Cloudinary Console > Settings > Security.",
        "docs": "https://cloudinary.com/documentation/solution_overview#account_and_api_setup"
    },

    # ── Generic — lower confidence, entropy-gated ──────────────────────────────
    "Hardcoded Password": {
        "pattern": r"(?i)(?:^|[^a-zA-Z])(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,64})['\"]",
        "severity": "medium", "category": "Generic",
        "min_entropy": 3.2, "min_length": 8, "allow_test": False,
        "description": "Hardcoded password in source code.",
        "remediation": "Move to environment variables. Use a secrets manager.",
        "docs": "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
    },
    "Generic API Key Assignment": {
        "pattern": r"(?i)(?:^|[^a-zA-Z])(?:api_key|apikey|api-key)\s*[=:]\s*['\"]([A-Za-z0-9+/=_\-]{20,})['\"]",
        "severity": "medium", "category": "Generic",
        "min_entropy": 3.5, "min_length": 20, "allow_test": False,
        "description": "Generic API key assignment in source code.",
        "remediation": "Move to environment variables or a secrets vault.",
        "docs": "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
    },
    "Generic Secret Assignment": {
        "pattern": r"(?i)(?:^|[^a-zA-Z])(?:secret_key|secretkey|app_secret)\s*[=:]\s*['\"]([A-Za-z0-9+/=_\-]{16,})['\"]",
        "severity": "medium", "category": "Generic",
        "min_entropy": 3.5, "min_length": 16, "allow_test": False,
        "description": "Generic hardcoded secret key.",
        "remediation": "Use environment variables. Add .env to .gitignore.",
        "docs": "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
    },
}

SEVERITY_WEIGHT = {"critical": 50, "high": 25, "medium": 10, "low": 3}

def calculate_risk_score(severity_counts: dict) -> int:
    raw = sum(SEVERITY_WEIGHT.get(sev, 0) * count for sev, count in severity_counts.items())
    return min(int(raw), 100)


def scan_content(content: str, filepath: str, job_id: str, full_name: str) -> list[dict]:
    """
    Scan file content against all patterns.
    Applies entropy gating, placeholder detection, and test-file confidence scoring.
    Returns list of finding dicts with fingerprints.
    """
    import hashlib
    findings = []
    lines    = content.splitlines()
    test_file = is_test_file(filepath)

    for name, cfg in SECRET_PATTERNS.items():
        try:
            for match in re.finditer(cfg["pattern"], content, re.MULTILINE):
                raw = match.group(0)

                # Extract the capture group if present (more precise entropy target)
                target = match.group(1) if match.lastindex and match.lastindex >= 1 else raw

                # Entropy gate
                ent = shannon_entropy(target)
                if cfg["min_entropy"] and ent < cfg["min_entropy"]:
                    continue

                # Length gate
                if cfg["min_length"] and len(target) < cfg["min_length"]:
                    continue

                # Placeholder filter
                if is_placeholder(target):
                    continue

                line_no   = content[: match.start()].count("\n") + 1
                ctx_start = max(0, line_no - 3)
                ctx_end   = min(len(lines), line_no + 2)

                masked = (target[:4] + "●" * max(0, len(target) - 8) + target[-4:]
                          ) if len(target) > 8 else "●" * len(target)

                # Confidence scoring
                if test_file and not cfg.get("allow_test", True):
                    confidence = "low"
                elif ent < (cfg["min_entropy"] or 0) + 0.5:
                    confidence = "medium"
                else:
                    confidence = "high"

                # Stable fingerprint: hash of (type + masked + file)
                fp_src    = f"{name}|{target}|{filepath}"
                fp        = hashlib.sha256(fp_src.encode()).hexdigest()[:16]

                findings.append({
                    "fingerprint":  fp,
                    "type":         name,
                    "category":     cfg["category"],
                    "severity":     cfg["severity"],
                    "description":  cfg["description"],
                    "remediation":  cfg["remediation"],
                    "docs":         cfg.get("docs", ""),
                    "file":         filepath,
                    "line":         line_no,
                    "masked":       masked,
                    "context":      "\n".join(lines[ctx_start:ctx_end]),
                    "entropy":      round(ent, 3),
                    "is_test_file": test_file,
                    "confidence":   confidence,
                })
        except re.error:
            continue

    return findings
