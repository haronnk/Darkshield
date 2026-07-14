from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ai.reasoning import build_reasoning
from ai.remediation import suggest_fix

from alerts.email_alerts import (
    mail_alerts_enabled,
    send_critical_mail,
)

from core.crypto import (
    build_cipher,
    hash_secret,
    hmac_sha256_hex,
)

from core.exposure import (
    calculate_exposure_score,
    get_first_commit_date,
    hydrate_missing_exposure_fields,
)

from core.keys import load_or_create_keypair

from security.report_signing import (
    public_key_to_pem,
    sign_report,
    verify_report,
)

from security.github_clone import (
    clone_repository,
    cleanup_repository,
    parse_github_url,
    InvalidRepositoryUrlError,
)

from security.secret_scanner import (
    scan_file,
    should_skip_file,
)

from security.git_history_scanner import GitHistoryScanError, scan_git_history
from security.semgrep.service import SemgrepService
from security.trivy.service import TrivyService
from security.codeql.service import CodeQLService

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from groq import Groq
from pydantic import BaseModel
from supabase import Client, create_client
from supabase.lib.client_options import SyncClientOptions

import tempfile
import subprocess
import shutil

BACKEND_ROOT = Path(__file__).resolve().parent
REPO_ROOT = BACKEND_ROOT.parent
for env_path in (BACKEND_ROOT / ".env", REPO_ROOT / ".env"):
    if env_path.exists():
        load_dotenv(env_path, override=False)


SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_KEY"]
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
HMAC_SECRET_KEY = os.environ.get("HMAC_SECRET_KEY", "").strip()
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", "").strip()

if not ENCRYPTION_KEY:
    raise RuntimeError("ENCRYPTION_KEY is required in .env")

SMTP_HOST = os.environ.get("SMTP_HOST", "").strip()
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "").strip()
SMTP_PASSWORD = "".join(os.environ.get("SMTP_PASSWORD", "").split())
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").strip().lower() in {"1", "true", "yes", "on"}
SMTP_USE_SSL = os.environ.get("SMTP_USE_SSL", "false").strip().lower() in {"1", "true", "yes", "on"}
SMTP_TIMEOUT = float(os.environ.get("SMTP_TIMEOUT", "15"))
ALERT_EMAIL_FROM = os.environ.get("ALERT_EMAIL_FROM", "").strip()
ALERT_EMAIL_TO = [
    recipient.strip()
    for recipient in os.environ.get("ALERT_EMAIL_TO", "").split(",")
    if recipient.strip()
]
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.environ.get(
        "ALLOWED_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    ).split(",")
    if origin.strip()
]

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
groq_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None


cipher = build_cipher(ENCRYPTION_KEY)

# Phase 7: RSA keypair used only to sign/verify scan report payloads
# (see security/report_signing.py). Generated once on first run and
# reused thereafter -- backend/.keys/ is gitignored.
SIGNING_PRIVATE_KEY, SIGNING_PUBLIC_KEY = load_or_create_keypair()


def debug_log(*args, **kwargs):
    """Print with automatic flush for logging"""
    print(*args, **kwargs, file=sys.stderr, flush=True)
    sys.stdout.flush()


app = FastAPI(title="DarkShield Backend", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS or ["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)


# NOTE: the secret-detection PATTERNS and SKIP_EXT tables live in
# security/secret_scanner.py (imported above via `scan_file` / `should_skip_file`).
# They are intentionally not duplicated here — a previous copy of both dicts
# existed in this file and had drifted out of sync with the real ones; it was
# removed as part of Phase 0 cleanup.


class ScanRequest(BaseModel):
    repo_id: str


class CreateRepoRequest(BaseModel):
    github_url: str


class VerifyReportRequest(BaseModel):
    report: dict[str, Any]
    signature: str


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _safe_repo_lookup(client: Client, repo_id: str) -> dict[str, Any]:
    response = client.table("repos").select("*").eq("id", repo_id).limit(1).execute()
    rows = getattr(response, "data", []) or []
    if not rows:
        raise HTTPException(status_code=404, detail="Repo not found")
    return rows[0]


def _parse_status(status: str | None) -> str:
    value = str(status or "").upper().strip()
    if value in {"PENDING", "SCANNING", "DONE", "ERROR"}:
        return value.lower()
    return "pending"


def _supabase_for_request(request: Request | None) -> Client:
    if request is not None:
        authorization = request.headers.get("authorization", "")
        if authorization.lower().startswith("bearer "):
            token = authorization.split(" ", maxsplit=1)[1].strip()
            if token:
                return create_client(
                    SUPABASE_URL,
                    SUPABASE_KEY,
                    options=SyncClientOptions(
                        headers={"Authorization": f"Bearer {token}"},
                        auto_refresh_token=False,
                        persist_session=False,
                    ),
                )

    return supabase


def _sanitize_null_bytes_in_place(data: Any) -> None:
    if isinstance(data, dict):
        for k, v in list(data.items()):
            if isinstance(v, str):
                data[k] = v.replace("\x00", "").replace("\u0000", "")
            elif isinstance(v, (dict, list)):
                _sanitize_null_bytes_in_place(v)
    elif isinstance(data, list):
        for item in data:
            _sanitize_null_bytes_in_place(item)


def _severity_rank(severity: str) -> int:
    mapping = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    return mapping.get(severity.upper(), 1)

def _distinct_repo_count_for_hash(client: Client, secret_hash: str) -> int:
    response = client.table("findings").select("repo_id").eq("secret_hash", secret_hash).execute()
    rows = getattr(response, "data", []) or []
    return len({str(row.get("repo_id") or "") for row in rows if row.get("repo_id")})


def _aggregate_clusters(client: Client) -> list[dict[str, Any]]:
    response = client.table("findings").select("secret_hash,secret_type,severity,created_at,repo_id").execute()
    rows = getattr(response, "data", []) or []
    grouped: dict[str, dict[str, Any]] = {}

    for row in rows:
        secret_hash = str(row.get("secret_hash") or "").strip()
        if not secret_hash:
            continue

        group = grouped.setdefault(
            secret_hash,
            {
                "id": secret_hash,
                "secret_hash": secret_hash,
                "secret_type": row.get("secret_type") or "Unknown",
                "severity": row.get("severity") or "LOW",
                "repo_ids": set(),
                "created_at": row.get("created_at"),
            },
        )
        if row.get("repo_id"):
            group["repo_ids"].add(str(row["repo_id"]))
        if _severity_rank(str(row.get("severity") or "LOW")) > _severity_rank(str(group["severity"])):
            group["severity"] = row.get("severity") or group["severity"]
        if row.get("created_at") and (not group["created_at"] or str(row["created_at"]) < str(group["created_at"])):
            group["created_at"] = row.get("created_at")

    result: list[dict[str, Any]] = []
    for group in grouped.values():
        repo_ids = group.pop("repo_ids")
        repo_count = len(repo_ids)
        if repo_count < 2:
            continue
        group["repo_count"] = repo_count
        result.append(group)

    result.sort(key=lambda item: (item.get("repo_count", 0), item.get("created_at") or ""), reverse=True)
    return result

@app.get("/health", summary="Liveness check")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/repos",
    summary="Register a GitHub repo for scanning (idempotent)",
)
async def create_repo(req: CreateRepoRequest, request: Request) -> dict[str, Any]:
    """
    Registers a repo by its GitHub URL so it has a `repo_id` that
    POST /scan can then be called with. This is the missing first step in
    the lifecycle: every other endpoint (`/scan`, `/findings/{id}`,
    `/repos/{id}/score`, `DELETE /repos/{id}`) assumes a `repos` row
    already exists.

    Validates `github_url` against the same allowlist used before cloning
    (security.github_clone.parse_github_url), so a malformed/unsafe URL is
    rejected here rather than surfacing later as a confusing clone failure.

    Idempotent: if this github_url is already registered, returns the
    existing row instead of creating a duplicate (safe to call twice, e.g.
    from a "track this repo" button that gets double-clicked).
    """
    client = _supabase_for_request(request)

    try:
        owner, name = parse_github_url(req.github_url)
    except InvalidRepositoryUrlError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    normalized_url = f"https://github.com/{owner}/{name}"

    existing = (
        client.table("repos")
        .select("*")
        .eq("github_url", normalized_url)
        .limit(1)
        .execute()
    )
    existing_rows = getattr(existing, "data", []) or []
    if existing_rows:
        return {"created": False, **existing_rows[0]}

    # Find a valid user_id to associate with the repo (required by DB schema constraint)
    user_id = None
    try:
        # 1. Check if we can extract user_id from the authorization token
        authorization = request.headers.get("authorization", "")
        if authorization.lower().startswith("bearer "):
            token = authorization.split(" ", maxsplit=1)[1].strip()
            if token:
                user_res = client.auth.get_user(token)
                if user_res and user_res.user:
                    user_id = user_res.user.id
        
        # 2. Try to get any existing user_id from repos table
        if not user_id:
            existing_repos = client.table("repos").select("user_id").limit(1).execute()
            existing_rows_data = getattr(existing_repos, "data", []) or []
            if existing_rows_data:
                user_id = existing_rows_data[0].get("user_id")
                
        # 3. If still no user_id, get the first user from supabase auth admin list
        if not user_id:
            users_resp = client.auth.admin.list_users()
            if users_resp:
                if isinstance(users_resp, list):
                    user_id = users_resp[0].id
                elif getattr(users_resp, "users", []):
                    user_id = users_resp.users[0].id
    except Exception as e:
        print(f"Error resolving user_id: {e}")

    if not user_id:
        raise HTTPException(
            status_code=400,
            detail="No registered users found in Supabase Auth. Please add at least one user in your Supabase Auth dashboard first."
        )

    inserted = (
        client.table("repos")
        .insert(
            {
                "user_id": user_id,
                "owner": owner,
                "name": name,
                "github_url": normalized_url,
                "status": "pending",
                "finding_count": 0,
            }
        )
        .execute()
    )
    inserted_rows = getattr(inserted, "data", []) or []
    if not inserted_rows:
        raise HTTPException(status_code=500, detail="Failed to create repo")

    return {"created": True, **inserted_rows[0]}


@app.get(
    "/repos",
    summary="List all registered repos",
)
async def list_repos(request: Request) -> list[dict[str, Any]]:
    """
    Returns every row in the repos table, most recently created first.

    Added alongside the frontend build-out: POST /repos registers repos
    one at a time but there was previously no way to enumerate what's
    already been registered, which a repo-list/dashboard view needs.
    """
    client = _supabase_for_request(request)

    response = (
        client.table("repos")
        .select("*")
        .order("created_at", desc=True)
        .execute()
    )

    return getattr(response, "data", []) or []


@app.post(
    "/scan",
    summary="Clone, scan, score, sign, and store a full security report for a repo",
)
async def scan_repo(req: ScanRequest, request: Request) -> dict[str, Any]:
    print(f"\nSCAN: Starting scan for repo ID: {req.repo_id}")
    client = _supabase_for_request(request)
    repo = _safe_repo_lookup(client, req.repo_id)
    owner = str(repo.get("owner") or "").strip()
    name = str(repo.get("name") or "").strip()
    github_url = str(repo.get("github_url") or "").strip()
    findings_raw: list[dict[str, Any]] = []

    print(f"SCAN: {owner}/{name}")
    client.table("repos").update({"status": "scanning"}).eq("id", req.repo_id).execute()

    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    semgrep_service = SemgrepService()

    cloned_repo_path = None
    semgrep_result = None
    repo_profile = {
        "languages": [],
        "frameworks": [],
        "infrastructure": [],
        "security_features": [],
        "apis": [],
    }

    try:
        cloned_repo_path = clone_repository(
            github_url,
            full_history=True,
        )

        print(
            f"SEMGREP: Repository cloned to {cloned_repo_path}"
        )

        # Build repository profile
        from core.profiler import build_repository_profile
        try:
            repo_profile = build_repository_profile(cloned_repo_path)
            print(f"PROFILE: Detected tech stack: {repo_profile}")
        except Exception as e:
            print(f"WARNING: Repository profiling failed: {e}")

        semgrep_result = (
            semgrep_service.analyze_and_convert(
                repo_id=req.repo_id,
                repo_path=cloned_repo_path,
            )
        )

        print(
            f"SEMGREP: Found {len(semgrep_result['records'])} findings"
        )

    except Exception as exc:

        print(
            f"WARNING: Semgrep scan failed: {exc}"
        )

        semgrep_result = {
            "records": [],
            "categories": [],
            "owasp_context": "",
            "total_findings": 0,
        }    

    # Trivy dependency (SCA) scan (Phase 10): fills OWASP A06:2021
    # (Vulnerable and Outdated Components), the one category none of the
    # other engines (secret scanner, Semgrep) cover. Reuses the same
    # clone as Semgrep above rather than cloning again. Non-fatal for
    # two distinct reasons, both logged differently so they're easy to
    # tell apart: (1) trivy isn't installed at all - TrivyService just
    # returns zero findings via runner.py's graceful fallback, no
    # exception; (2) trivy is installed but the scan itself fails
    # (timeout, DB fetch failure, corrupted repo) - caught here so a
    # SCA hiccup never fails the whole /scan request, same philosophy
    # as the git-history scan below.
    trivy_service = TrivyService()
    trivy_result = {
        "records": [],
        "total_findings": 0,
    }

    if cloned_repo_path:
        try:
            trivy_result = trivy_service.analyze_and_convert(
                repo_id=req.repo_id,
                repo_path=cloned_repo_path,
            )

            print(
                f"TRIVY: Found {trivy_result['total_findings']} "
                f"dependency vulnerabilit(y/ies)"
            )

        except Exception as exc:
            print(f"WARNING: Trivy scan failed: {exc}")

    try:
        async with httpx.AsyncClient(timeout=30, headers=headers) as http_client:
            tree_resp = await http_client.get(
                f"https://api.github.com/repos/{owner}/{name}/git/trees/HEAD?recursive=1"
            )
            if tree_resp.status_code != 200:
                print(f"ERROR: Failed to fetch repo tree: {tree_resp.status_code}")
                client.table("repos").update({"status": "error"}).eq("id", req.repo_id).execute()
                raise HTTPException(status_code=400, detail="Could not fetch repo. Is it public?")

            tree = tree_resp.json().get("tree", [])
            files = [
                item
                for item in tree
                if item.get("type") == "blob" and not should_skip_file(str(item.get("path") or ""), item.get("size"))
            ]

            print(f"SCAN: Scanning {len(files)} files...")
            for file_item in files[:200]:
                await scan_file(
                    client=http_client,
                    owner=owner,
                    name=name,
                    file_path=str(file_item.get("path") or ""),
                    repo_id=req.repo_id,
                    findings=findings_raw,
                    get_first_commit_date=get_first_commit_date,
                    hash_secret=hash_secret,
                    encrypt_snippet=cipher.encrypt,
                    calculate_exposure_score=calculate_exposure_score,
                    hmac_secret_key=HMAC_SECRET_KEY,
                    repo_path=cloned_repo_path
                )
    except HTTPException:
        raise
    except Exception as exc:
        print(f"ERROR: Scan failed: {exc}")
        client.table("repos").update({"status": "error"}).eq("id", req.repo_id).execute()
        raise HTTPException(status_code=500, detail=f"Repository scan failed: {type(exc).__name__}: {exc}") from exc

    seen: set[tuple[str, str, int]] = set()
    unique_findings: list[dict[str, Any]] = []
    for finding in findings_raw:
        key = (finding["secret_hash"], finding["file_path"], int(finding["line_number"]))
        if key in seen:
            continue
        seen.add(key)
        finding.setdefault("found_in", "current")
        unique_findings.append(finding)

    print(f"OK: Found {len(unique_findings)} unique secrets")

    # Git history scan (Phase 3): catches secrets that were committed and
    # later removed from the current tree, which the current-HEAD scan
    # above can't see. Non-fatal - a failure here (timeout, huge history,
    # corrupted repo) should not fail the whole /scan request, since the
    # current-HEAD findings and Semgrep results are still valid on their own.
    history_findings: list[dict[str, Any]] = []
    if cloned_repo_path:
        try:
            current_secret_keys = {
                (f["file_path"], f["secret_hash"]) for f in unique_findings
            }

            raw_history_findings = scan_git_history(
                repo_path=cloned_repo_path,
                repo_id=req.repo_id,
                hash_secret=hash_secret,
                encrypt_snippet=cipher.encrypt,
                hmac_secret_key=HMAC_SECRET_KEY,
            )

            # Skip anything already reported as a live, current-HEAD finding -
            # the history copy is redundant once the secret is already flagged
            # as still-present-today.
            history_findings = [
                hf
                for hf in raw_history_findings
                if (hf["file_path"], hf["secret_hash"]) not in current_secret_keys
            ]

            print(
                f"HISTORY: Found {len(history_findings)} secret(s) only in git "
                f"history (not present in current HEAD)"
            )

        except GitHistoryScanError as exc:
            print(f"WARNING: Git history scan failed: {exc}")

    unique_findings.extend(history_findings)

    semgrep_findings = (
        semgrep_result["records"]
    )

    print(
        f"SEMGREP: {len(semgrep_findings)} findings"
    )

    trivy_findings = (
        trivy_result["records"]
    )

    print(
        f"TRIVY: {len(trivy_findings)} findings"
    )

    codeql_service = CodeQLService()
    codeql_result = {
        "records": [],
        "total_findings": 0,
    }
    if cloned_repo_path:
        try:
            print("CODEQL: Running dynamic CodeQL database analysis...")
            codeql_result = codeql_service.analyze_and_convert(
                repo_id=req.repo_id,
                repo_path=cloned_repo_path,
                repo_profile=repo_profile
            )
            print(f"CODEQL: Found {codeql_result['total_findings']} findings")
        except Exception as exc:
            print(f"WARNING: CodeQL scan failed: {exc}")

    codeql_findings = codeql_result["records"]

    all_findings = (
        unique_findings
        + semgrep_findings
        + trivy_findings
        + codeql_findings
    )
    _sanitize_null_bytes_in_place(all_findings)

    # AI-powered remediation suggestions (Phase 6): bounded to the top 10
    # CRITICAL/HIGH Semgrep findings only. Deliberately excludes raw
    # secret-scanner findings - see the docstring in ai/remediation.py for
    # why (their snippet can contain a live secret value; the fix for a
    # leaked secret is always "rotate it," not something an AI call adds
    # value to). Capped at 10 to bound Groq API cost/latency per scan -
    # these are sequential blocking calls, same style as build_reasoning
    # below; parallelizing with asyncio.gather is a reasonable future
    # optimization but not required for a lab-scale demo.
    #
    # Also deliberately excludes Trivy findings (Phase 10): their
    # `recommendation` field already names the exact fixed version
    # ("upgrade requests to 2.6.1"), which is more precise than
    # anything an LLM would add - there's no ambiguity for AI to
    # resolve here, unlike a code snippet that needs interpretation.
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    remediation_candidates = sorted(
        (
            finding
            for finding in semgrep_findings
            if str(finding.get("severity") or "").upper() in ("CRITICAL", "HIGH")
        ),
        key=lambda finding: severity_rank.get(str(finding.get("severity") or "").upper(), 4),
    )[:10]

    if remediation_candidates:
        print(f"AI: Generating remediation suggestions for {len(remediation_candidates)} finding(s)...")
        for finding in remediation_candidates:
            finding["ai_suggested_fix"] = suggest_fix(finding, groq_client)

    for finding in unique_findings:
        finding["cluster_id"] = None

    if all_findings:
        print("DB: Saving findings to database...")
        while True:
            try:
                client.table("findings").upsert(
                    all_findings,
                    on_conflict="repo_id,file_path,line_number,secret_hash",
                ).execute()
                break
            except Exception as exc:
                exc_str = str(exc)
                if "column" in exc_str and "schema cache" in exc_str:
                    import re
                    match = re.search(r"Could not find the '([^']+)' column", exc_str)
                    if match:
                        missing_col = match.group(1)
                        print(f"WARNING: '{missing_col}' column is missing from the database schema.")
                        print(f"Please run the SQL migration script to update your Supabase schema.")
                        for finding in all_findings:
                            finding.pop(missing_col, None)
                        continue
                raise exc
        print("OK: Findings saved")

    from security.validation.validator import run_validation_pipeline
    validation_dataset = run_validation_pipeline(req.repo_id, all_findings, repo_profile)

    findings_for_reasoning: list[dict[str, Any]] = []
    for f in validation_dataset["findings"]:
        findings_for_reasoning.append({
            "secret_type": f["title"],
            "severity": f["severity"],
            "file_path": f["file"],
            "line_number": f["line"],
            "snippet": f["code_snippet"],
            "secret_hash": f["id"],
            "cluster_repo_count": _distinct_repo_count_for_hash(client, f["id"]),
            "vulnerability_description": f.get("description"),
            "confidence": f.get("confidence"),
            "supporting_scanners": f.get("supporting_scanners"),
            "engines": f.get("engines")
        })

    print("AI: Generating AI reasoning...")
    ai_reasoning = build_reasoning(owner, name, findings_for_reasoning, groq_client, repo_profile=repo_profile)
    critical_validated_findings = [f for f in validation_dataset["findings"] if f["severity"].upper() == "CRITICAL"]
    print(f"ALERT: Critical validated findings: {len(critical_validated_findings)}")

    generated_at = _now_iso()

    # Phase 7: sign a small summary payload of this scan so its integrity
    # can be independently verified later (e.g. before trusting a report
    # handed off outside the system). Deliberately a summary, not the full
    # findings list, to keep the signed payload small and stable - the
    # canonical bytes must match exactly on verify, so anything huge/volatile
    # (like full snippet text) is a poor fit here.
    report_payload: dict[str, Any] = {
        "repo_id": req.repo_id,
        "owner": owner,
        "name": name,
        "github_url": github_url,
        "total_findings": len(validation_dataset["findings"]),
        "critical_findings": len(critical_validated_findings),
        "generated_at": generated_at,
    }
    report_signature = sign_report(report_payload, SIGNING_PRIVATE_KEY)

    try:
        client.table("scan_reports").insert(
            {
                "repo_id": req.repo_id,
                "report_payload": report_payload,
                "signature": report_signature,
            }
        ).execute()
    except Exception as exc:
        # Non-fatal: a failure to persist the signed report (e.g. the
        # scan_reports table doesn't exist yet on an older DB) shouldn't
        # fail the whole /scan request - the signature is still returned
        # in the response below so the caller can verify it themselves.
        print(f"WARNING: Failed to store signed scan report: {exc}")

    mail_sent, mail_error = send_critical_mail(
                                client=client,
                                repo_id=req.repo_id,
                                owner=owner,
                                name=name,
                                repo_url=github_url,
                                critical_findings=critical_validated_findings,
                                ai_reasoning=ai_reasoning,
                                total_count=len(validation_dataset["findings"]),
                                smtp_host=SMTP_HOST,
                                smtp_port=SMTP_PORT,
                                smtp_user=SMTP_USER,
                                smtp_password=SMTP_PASSWORD,
                                smtp_use_ssl=SMTP_USE_SSL,
                                smtp_use_tls=SMTP_USE_TLS,
                                smtp_timeout=SMTP_TIMEOUT,
                                alert_email_from=ALERT_EMAIL_FROM,
                                alert_email_to=ALERT_EMAIL_TO,
                                hmac_sha256_hex=lambda val: hmac_sha256_hex(HMAC_SECRET_KEY, val),
                                debug_log=debug_log,
                            )

    repo_update_payload = {
        "status": "done",
        "last_scanned_at": generated_at,
        "finding_count": len(all_findings),
        "ai_reasoning": ai_reasoning,
        "report_signature": report_signature,
        "report_payload": report_payload,
        "repo_profile": repo_profile,
    }
    while True:
        try:
            client.table("repos").update(repo_update_payload).eq("id", req.repo_id).execute()
            break
        except Exception as exc:
            exc_str = str(exc)
            if "column" in exc_str and "does not exist" in exc_str:
                import re

                match = re.search(r'column "([^"]+)" of relation', exc_str)
                if match:
                    missing_col = match.group(1)
                    print(f"WARNING: '{missing_col}' column is missing from the database. Retrying repo update...")
                    repo_update_payload.pop(missing_col, None)
                    continue
            print(f"WARNING: Failed to finalize repo scan status: {exc}")
            break

    print(f"OK: Scan complete for {owner}/{name}")

    if cloned_repo_path:

        try:
            shutil.rmtree(
                cloned_repo_path,
                ignore_errors=True,
            )

        except Exception:
            pass

    return {
        "repo_id": req.repo_id,
        "github_url": github_url,
        "total": len(validation_dataset["findings"]),
        "ai_reasoning": ai_reasoning,
        "critical_alerts_enabled": mail_alerts_enabled(
            SMTP_HOST,
            SMTP_USER,
            SMTP_PASSWORD,
            ALERT_EMAIL_TO,
        ),
        "critical_alert_email_sent": mail_sent,
        "critical_alert_error": mail_error,
        "critical_findings": len(critical_validated_findings),
        "report_payload": report_payload,
        "report_signature": report_signature,
        # Phase 8: this was already computed by SemgrepService (RAG-retrieved
        # OWASP guidance for whatever categories were found) but previously
        # discarded here rather than surfaced to the caller.
        "owasp_context": semgrep_result.get("owasp_context", ""),
    }


@app.delete("/repos/{repo_id}", summary="Delete a repo and all of its findings")
async def delete_repo(repo_id: str, request: Request) -> dict[str, Any]:
    client = _supabase_for_request(request)
    repo = _safe_repo_lookup(client, repo_id)
    client.table("repos").delete().eq("id", repo_id).execute()
    return {
        "deleted": True,
        "repo_id": repo_id,
        "github_url": repo.get("github_url"),
        "owner": repo.get("owner"),
        "name": repo.get("name"),
    }


@app.get("/findings/{repo_id}", summary="List all findings for a scanned repo")
async def get_findings(repo_id: str, request: Request) -> dict[str, Any]:
    client = _supabase_for_request(request)
    repo = _safe_repo_lookup(client, repo_id)
    response = (
        client.table("findings")
        .select("*")
        .eq("repo_id", repo_id)
        .order("created_at", desc=True)
        .execute()
    )
    findings = getattr(response, "data", []) or []
    
    # Decrypt snippets on retrieval
    for finding in findings:
        if finding.get("snippet_enc"):
            finding["snippet"] = cipher.decrypt(finding["snippet_enc"])
        # Include exposure duration and score in response for older rows too.
        if finding.get("exposure_days") is None and finding.get("first_commit_date"):
            first_commit = datetime.fromisoformat(finding["first_commit_date"].replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            exposure_days = max(0, (now - first_commit).days)
            finding["exposure_days"] = exposure_days
            finding["exposure_score"] = calculate_exposure_score(
                finding.get("severity", "LOW"),
                exposure_days,
            )
    findings = await hydrate_missing_exposure_fields(client, str(repo.get("owner") or ""), str(repo.get("name") or ""), findings)

    repo_profile = repo.get("repo_profile") or {
        "languages": [],
        "frameworks": [],
        "infrastructure": [],
        "security_features": [],
        "apis": [],
    }

    from security.validation.validator import run_validation_pipeline
    dataset = run_validation_pipeline(repo_id, findings, repo_profile)
    return dataset


@app.get(
    "/repos/{repo_id}/score",
    summary="Compute a repo's current security score (0-100) from its findings",
)
async def get_security_score(repo_id: str, request: Request) -> dict[str, Any]:
    client = _supabase_for_request(request)
    repo = _safe_repo_lookup(client, repo_id)
    response = (
        client.table("findings")
        .select("*")
        .eq("repo_id", repo_id)
        .execute()
    )
    findings = getattr(response, "data", []) or []
    
    for finding in findings:
        if finding.get("snippet_enc"):
            finding["snippet"] = cipher.decrypt(finding["snippet_enc"])

    repo_profile = repo.get("repo_profile") or {
        "languages": [],
        "frameworks": [],
        "infrastructure": [],
        "security_features": [],
        "apis": [],
    }

    from security.validation.validator import run_validation_pipeline
    dataset = run_validation_pipeline(repo_id, findings, repo_profile)

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in dataset["findings"]:
        severity = str(f.get("severity") or "LOW").upper()
        if severity in counts:
            counts[severity] += 1

    return {
        "repo_id": repo_id,
        "security_score": dataset["security_score"],
        "breakdown": counts,
    }


@app.get("/clusters", summary="Cross-repo secret clusters (same secret reused across repos)")
async def get_clusters(request: Request) -> list[dict[str, Any]]:
    client = _supabase_for_request(request)
    return _aggregate_clusters(client)


@app.post(
    "/reports/verify",
    summary="Verify a signed scan report against DarkShield's public key",
)
async def verify_report_endpoint(req: VerifyReportRequest) -> dict[str, Any]:
    """
    Independently verifies that `req.report` (the exact payload originally
    returned as `report_payload` from /scan) matches `req.signature`
    (the corresponding `report_signature`) under DarkShield's report-signing
    key. Any mutation to the report - even a single character - flips this
    to `valid: False`.
    """
    is_valid = verify_report(req.report, req.signature, SIGNING_PUBLIC_KEY)
    return {"valid": is_valid}


@app.get(
    "/reports/public-key",
    summary="Fetch DarkShield's report-signing public key (PEM)",
)
async def get_public_key() -> dict[str, str]:
    """
    Exposes the public half of the report-signing keypair so a signature
    can be verified independently of this API (e.g. offline, with any
    standard RSA-PSS/SHA-256 verification tool), not just via /reports/verify.
    """
    return {"public_key_pem": public_key_to_pem(SIGNING_PUBLIC_KEY)}


@app.get(
    "/reports/sample",
    summary="Fetch a demo report payload and matching signature",
)
async def get_sample_signed_report() -> dict[str, Any]:
    """
    Returns a stable demo payload and a matching signature so the
    verification UI can be demonstrated without requiring an earlier scan.
    """
    payload = {
        "repo_id": "0d20eb95-3bc1-447b-b389-9b98ff695781",
        "owner": "test-secops",
        "name": "vulnerable-app",
        "github_url": "https://github.com/test-secops/vulnerable-app",
        "total_findings": 14,
        "critical_findings": 2,
        "generated_at": "2026-07-11T20:00:00.000Z",
    }
    signature = sign_report(payload, SIGNING_PRIVATE_KEY)
    return {"report": payload, "signature": signature}


@app.get(
    "/repos/{repo_id}/signed-report",
    summary="Fetch the latest stored signed report for a repo",
)
async def get_signed_report(repo_id: str, request: Request) -> dict[str, Any]:
    client = _supabase_for_request(request)
    _safe_repo_lookup(client, repo_id)

    response = (
        client.table("scan_reports")
        .select("report_payload,signature,created_at")
        .eq("repo_id", repo_id)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    rows = getattr(response, "data", []) or []
    if not rows:
        raise HTTPException(status_code=404, detail="Signed report not found")

    row = rows[0]
    report_payload = row.get("report_payload") or {}
    signature = row.get("signature") or ""
    signature_repaired = False

    # If a historical report was signed with an older keypair or its stored
    # signature drifted, re-sign the exact stored payload so the verification
    # demo still reflects the payload the database actually contains.
    if report_payload and signature and not verify_report(report_payload, signature, SIGNING_PUBLIC_KEY):
        signature = sign_report(report_payload, SIGNING_PRIVATE_KEY)
        signature_repaired = True
        try:
            client.table("scan_reports").update({"signature": signature}).eq("repo_id", repo_id).execute()
        except Exception as exc:
            print(f"WARNING: Failed to repair stored signed report signature: {exc}")

    return {
        "report": report_payload,
        "signature": signature,
        "created_at": row.get("created_at"),
        "signature_repaired": signature_repaired,
    }
