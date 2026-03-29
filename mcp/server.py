"""
Kinetic MCP Gate — FastMCP server exposing pentesting tools to Claude.

Each tool dispatches work to the Strike Engine API and polls for results.

v0.3.0: Workspace-backed cloning, list_files, scan_api (KiteRunner),
        renamed tool surface (audit_code, check_secrets, find_subdomains,
        find_params), tool-chain instructions.

TOOL-CHAIN WORKFLOW — Auditing a Repository:
    1. Use clone_repo to clone the target repository into an isolated workspace.
    2. Use list_files to explore the directory tree and understand the codebase
       structure (languages, frameworks, config files, sensitive paths).
    3. Use audit_code to run Semgrep static analysis on the workspace path,
       choosing an appropriate ruleset based on what list_files revealed.
    4. Use check_secrets to scan the repo for leaked credentials and API keys.
    5. Optionally use delete_workspace when finished to free disk space.

    For web targets:
    - Root domain (example.com) → find_subdomains first, then vuln_scan each.
    - URL endpoint → find_params to discover hidden parameters, then vuln_scan.
    - API base URL → scan_api to brute-force API routes.
"""

from __future__ import annotations

import asyncio
import json
import os
import re

import httpx
from mcp.server.fastmcp import FastMCP

ENGINE_URL = os.getenv("KINETIC_ENGINE_URL", "http://localhost:8000")
SELENIUM_URL = os.getenv("SELENIUM_URL", "http://localhost:4444")
POLL_INTERVAL = 2.0
POLL_TIMEOUT = 300.0

mcp = FastMCP(
    "Kinetic Gate",
    instructions=(
        "Kinetic is an offensive security MCP gateway for authorized pentesting.\n\n"
        "TOOL-CHAIN WORKFLOW — To audit a repository:\n"
        "  1. clone_repo → clone the target into an isolated workspace\n"
        "  2. list_files → explore the tree to understand structure and languages\n"
        "  3. audit_code → run Semgrep on the workspace path for vulnerabilities\n"
        "  4. check_secrets → scan for leaked credentials and API keys\n"
        "  5. delete_workspace → clean up when done\n\n"
        "TOOL SELECTION:\n"
        "  - File path or git URL → clone_repo, then audit_code / check_secrets\n"
        "  - Root domain (example.com) → find_subdomains, then vuln_scan each\n"
        "  - URL endpoint → find_params to find hidden parameters, then vuln_scan\n"
        "  - API base URL → scan_api to brute-force API routes\n"
        "  - IP or CIDR → port_scan\n"
        "  - Any running scan → abort_scan to stop it"
    ),
)


# ── Shared Helpers ───────────────────────────────────────────────────────────


async def _execute_and_wait(
    tool: str,
    target: str,
    flags: list[str] | None = None,
) -> dict:
    """Submit a job to the Strike Engine and poll until it finishes."""
    async with httpx.AsyncClient(base_url=ENGINE_URL, timeout=10.0) as client:
        resp = await client.post(
            "/execute",
            json={"tool": tool, "target": target, "flags": flags or []},
        )
        resp.raise_for_status()
        task_id = resp.json()["task_id"]

        elapsed = 0.0
        while elapsed < POLL_TIMEOUT:
            await asyncio.sleep(POLL_INTERVAL)
            elapsed += POLL_INTERVAL
            status_resp = await client.get(f"/tasks/{task_id}")
            status_resp.raise_for_status()
            data = status_resp.json()

            if data["status"] in ("completed", "failed", "cancelled"):
                logs_resp = await client.get(f"/tasks/{task_id}/logs")
                raw_output = logs_resp.text if logs_resp.status_code == 200 else ""
                return {**data, "raw_output": raw_output}

        return {"task_id": task_id, "status": "timeout", "raw_output": ""}


def _format_result(result: dict) -> str:
    """Return parsed JSON if available, else raw output."""
    parsed = result.get("parsed_output")
    if parsed:
        return json.dumps(parsed, indent=2, default=str)
    return result.get("raw_output", "No output.")


async def _wait_for_workspace(workspace_id: str, timeout: float = 60.0) -> dict:
    """Poll workspace status until it is ready or failed."""
    async with httpx.AsyncClient(base_url=ENGINE_URL, timeout=10.0) as client:
        elapsed = 0.0
        while elapsed < timeout:
            resp = await client.get(f"/workspace/{workspace_id}")
            resp.raise_for_status()
            data = resp.json()
            if data["status"] in ("ready", "failed"):
                return data
            await asyncio.sleep(1.0)
            elapsed += 1.0
        return {"status": "timeout", "error": "Clone timed out"}


# ═════════════════════════════════════════════════════════════════════════════
# WORKSPACE TOOLS
# ═════════════════════════════════════════════════════════════════════════════


@mcp.tool()
async def clone_repo(
    repo_url: str,
    ttl: int = 3600,
) -> str:
    """
    Clone a git repository into an isolated workspace for analysis.

    This is the FIRST step in the repo audit workflow. After cloning,
    use list_files to explore the structure, then audit_code / check_secrets.

    Args:
        repo_url: Git repository URL (https:// or git@).
        ttl: Time-to-live in seconds before auto-cleanup (default: 1 hour).

    Returns:
        JSON with workspace_id (use this for subsequent tools) and path.
    """
    async with httpx.AsyncClient(base_url=ENGINE_URL, timeout=10.0) as client:
        resp = await client.post(
            "/workspace/clone",
            json={"repo_url": repo_url, "ttl": ttl},
        )
        resp.raise_for_status()
        ws = resp.json()

    # Wait for the clone to finish.
    final = await _wait_for_workspace(ws["workspace_id"])

    if final["status"] == "failed":
        return json.dumps({
            "status": "failed",
            "error": final.get("error", "Clone failed"),
        })

    return json.dumps({
        "workspace_id": ws["workspace_id"],
        "repo_url": repo_url,
        "path": ws["path"],
        "status": final["status"],
        "ttl": ttl,
    }, indent=2)


@mcp.tool()
async def list_files(
    workspace_id: str,
    subpath: str = "",
    max_depth: int = 3,
) -> str:
    """
    List files inside a cloned workspace to understand the codebase structure.

    Use this AFTER clone_repo and BEFORE audit_code so you know which
    languages, frameworks, and sensitive files are present.

    Args:
        workspace_id: The workspace_id returned by clone_repo.
        subpath: Optional subdirectory to list (e.g. "src/").
        max_depth: Maximum directory depth to traverse (default: 3).

    Returns:
        JSON tree of files with paths, types, and sizes.
    """
    async with httpx.AsyncClient(base_url=ENGINE_URL, timeout=10.0) as client:
        resp = await client.get(
            f"/workspace/{workspace_id}/files",
            params={"subpath": subpath, "max_depth": max_depth},
        )
        if resp.status_code == 404:
            return json.dumps({"error": "Workspace not found or not ready."})
        resp.raise_for_status()
        return json.dumps(resp.json(), indent=2)


@mcp.tool()
async def delete_workspace(workspace_id: str) -> str:
    """
    Delete a workspace and free its disk space.

    Use this when you are finished analyzing a cloned repository.

    Args:
        workspace_id: The workspace_id to delete.
    """
    async with httpx.AsyncClient(base_url=ENGINE_URL, timeout=10.0) as client:
        resp = await client.delete(f"/workspace/{workspace_id}")
        if resp.status_code == 404:
            return f"Workspace {workspace_id} not found."
        resp.raise_for_status()
        return f"Workspace {workspace_id} deleted."


# ═════════════════════════════════════════════════════════════════════════════
# SCANNING TOOLS
# ═════════════════════════════════════════════════════════════════════════════


# ── Port Scan (Nmap) ────────────────────────────────────────────────────────


@mcp.tool()
async def port_scan(
    target: str,
    ports: str = "-",
    service_detection: bool = True,
    timing: int = 4,
) -> str:
    """
    Run an Nmap port scan against a target host or network.

    Returns structured XML-parsed JSON when available, otherwise raw output.

    Args:
        target: IP address, hostname, or CIDR range to scan.
        ports: Port specification (e.g. "80,443", "1-1024", or "-" for all).
        service_detection: Enable service/version detection (-sV).
        timing: Nmap timing template (0-5, default 4).
    """
    flags = ["-p", ports, f"-T{timing}"]
    if service_detection:
        flags.append("-sV")

    result = await _execute_and_wait("nmap", target, flags)
    if result["status"] == "failed":
        return f"Scan failed: {result.get('error', 'unknown error')}\n{result['raw_output']}"
    return _format_result(result)


# ── Vuln Scan (Nuclei) ──────────────────────────────────────────────────────


@mcp.tool()
async def vuln_scan(
    target: str,
    severity: str = "medium,high,critical",
    tags: str = "",
) -> str:
    """
    Run a Nuclei vulnerability scan against a target URL.

    Returns structured JSONL-parsed results when available.

    Args:
        target: The URL to scan (e.g. https://example.com).
        severity: Comma-separated severity filter (info,low,medium,high,critical).
        tags: Comma-separated template tags to include (e.g. "cve,oast").
    """
    flags = ["-severity", severity]
    if tags:
        flags.extend(["-tags", tags])

    result = await _execute_and_wait("nuclei", target, flags)
    if result["status"] == "failed":
        return f"Scan failed: {result.get('error', 'unknown error')}\n{result['raw_output']}"
    return _format_result(result)


# ── Code Audit (Semgrep) ────────────────────────────────────────────────────


@mcp.tool()
async def audit_code(
    path: str,
    config: str = "p/default",
    severity: str = "",
) -> str:
    """
    Run Semgrep static analysis on a codebase for vulnerabilities.

    Use this AFTER clone_repo and list_files. Pass the workspace path
    returned by clone_repo.

    Recommended rulesets based on what list_files reveals:
    - Python/JS/Go/Java → "p/default" or "p/owasp-top-ten"
    - Security-focused  → "p/security-audit"
    - CI pipeline       → "p/ci"

    Args:
        path: Workspace path to scan (from clone_repo's response).
        config: Semgrep ruleset (e.g. "p/default", "p/owasp-top-ten").
        severity: Filter by severity (e.g. "ERROR", "WARNING").
    """
    flags = ["--config", config]
    if severity:
        flags.extend(["--severity", severity])

    result = await _execute_and_wait("semgrep", path, flags)
    if result["status"] == "failed":
        return f"Audit failed: {result.get('error', 'unknown error')}\n{result['raw_output']}"

    parsed = result.get("parsed_output")
    if parsed and isinstance(parsed, dict):
        findings = parsed.get("results", [])
        summary = {
            "total_findings": len(findings),
            "findings": [
                {
                    "rule": f.get("check_id", "unknown"),
                    "severity": f.get("extra", {}).get("severity", "unknown"),
                    "message": f.get("extra", {}).get("message", ""),
                    "file": f.get("path", ""),
                    "line": f.get("start", {}).get("line"),
                    "code": f.get("extra", {}).get("lines", ""),
                }
                for f in findings
            ],
        }
        return json.dumps(summary, indent=2)
    return result.get("raw_output") or "No findings."


# ── Secret Scanning (Gitleaks) ──────────────────────────────────────────────


@mcp.tool()
async def check_secrets(
    path: str,
    no_git: bool = False,
) -> str:
    """
    Scan a repository or directory for leaked secrets and credentials.

    Pass the workspace path from clone_repo. Returns structured "Leaked
    Secret" objects with Type, File, and Line Number.

    Args:
        path: Workspace path to scan (from clone_repo's response).
        no_git: If true, scan files without requiring a .git directory.
    """
    flags = []
    if no_git:
        flags.append("--no-git")

    result = await _execute_and_wait("gitleaks", path, flags)

    # Gitleaks exits with code 1 when leaks are found (not a real error).
    parsed = result.get("parsed_output")
    if parsed and isinstance(parsed, list):
        leaks = [
            {
                "type": entry.get("RuleID", "unknown"),
                "file": entry.get("File", ""),
                "line_number": entry.get("StartLine"),
                "match": entry.get("Match", ""),
                "secret": entry.get("Secret", "")[0:8] + "***" if entry.get("Secret") else "",
                "commit": entry.get("Commit", "")[:12],
                "author": entry.get("Author", ""),
            }
            for entry in parsed
        ]
        return json.dumps({
            "total_leaks": len(leaks),
            "leaks": leaks,
        }, indent=2)

    if result["status"] == "failed" and result.get("return_code") == 1:
        return result.get("raw_output") or "Leaks detected (see raw output)."

    if result["status"] == "failed":
        return f"Scan failed: {result.get('error', 'unknown error')}\n{result['raw_output']}"

    return "No secrets detected."


# ── Subdomain Enumeration (Subfinder) ───────────────────────────────────────


@mcp.tool()
async def find_subdomains(
    domain: str,
    recursive: bool = False,
) -> str:
    """
    Enumerate subdomains for a root domain using passive sources.

    Use this when given a root domain like example.com. Follow up with
    vuln_scan or port_scan on discovered subdomains.

    Args:
        domain: Root domain to enumerate (e.g. example.com).
        recursive: Enable recursive subdomain enumeration.
    """
    flags = ["-silent"]
    if recursive:
        flags.append("-recursive")

    result = await _execute_and_wait("subfinder", domain, flags)
    if result["status"] == "failed":
        return f"Enumeration failed: {result.get('error', 'unknown error')}\n{result['raw_output']}"

    parsed = result.get("parsed_output")
    if parsed and isinstance(parsed, list):
        subdomains = [
            entry.get("host", entry) if isinstance(entry, dict) else entry
            for entry in parsed
        ]
        return json.dumps({
            "domain": domain,
            "total_subdomains": len(subdomains),
            "subdomains": subdomains,
        }, indent=2)
    return result.get("raw_output") or "No subdomains found."


# ── Hidden Parameter Discovery (Arjun) ──────────────────────────────────────


@mcp.tool()
async def find_params(
    url: str,
    method: str = "GET",
    wordlist: str = "",
) -> str:
    """
    Discover hidden HTTP parameters on a URL endpoint.

    Args:
        url: Target URL to probe (e.g. https://example.com/api/search).
        method: HTTP method to use (GET, POST, JSON).
        wordlist: Path to custom wordlist (optional, uses built-in by default).
    """
    flags = ["-m", method]
    if wordlist:
        flags.extend(["-w", wordlist])

    result = await _execute_and_wait("arjun", url, flags)
    if result["status"] == "failed":
        return f"Discovery failed: {result.get('error', 'unknown error')}\n{result['raw_output']}"
    return _format_result(result)


# ── API Endpoint Brute-Force (KiteRunner) ────────────────────────────────────


@mcp.tool()
async def scan_api(
    url: str,
    wordlist: str = "",
    assetnote_wordlist: str = "apiroutes-210228",
    concurrency: int = 3,
) -> str:
    """
    Brute-force API endpoints on a target URL using KiteRunner.

    Discovers hidden API routes by replaying request patterns from
    OpenAPI/Swagger schemas and curated wordlists.

    Args:
        url: Base URL of the API to scan (e.g. https://api.example.com).
        wordlist: Path to a custom wordlist file (-w). Overrides assetnote_wordlist.
        assetnote_wordlist: Built-in Assetnote wordlist name (-A). Default: apiroutes-210228.
        concurrency: Max parallel hosts (-j). Default: 3.
    """
    flags = ["-j", str(concurrency), "-q"]
    if wordlist:
        flags.extend(["-w", wordlist])
    else:
        flags.extend(["-A", assetnote_wordlist])

    result = await _execute_and_wait("kiterunner", url, flags)
    if result["status"] == "failed":
        return f"API scan failed: {result.get('error', 'unknown error')}\n{result['raw_output']}"

    parsed = result.get("parsed_output")
    if parsed and isinstance(parsed, list):
        routes = [
            {
                "method": entry.get("method", ""),
                "path": entry.get("path", ""),
                "status": entry.get("status_code"),
                "length": entry.get("content_length"),
            }
            for entry in parsed
        ]
        return json.dumps({
            "url": url,
            "total_routes": len(routes),
            "routes": routes,
        }, indent=2)
    return _format_result(result)


# ── Abort Scan (Emergency Brake) ────────────────────────────────────────────


@mcp.tool()
async def abort_scan(task_id: str, force: bool = False) -> str:
    """
    Emergency brake — immediately terminate a running scan.

    Sends SIGTERM (graceful) or SIGKILL (force) to the underlying process.

    Args:
        task_id: The task ID returned by a previous scan invocation.
        force: If true, send SIGKILL instead of SIGTERM.
    """
    async with httpx.AsyncClient(base_url=ENGINE_URL, timeout=10.0) as client:
        resp = await client.delete(
            f"/execute/{task_id}",
            params={"force": str(force).lower()},
        )
        if resp.status_code == 404:
            return f"Task {task_id} not found."
        if resp.status_code == 409:
            return f"Task {task_id} is not running (already {resp.json().get('detail', 'finished')})."
        resp.raise_for_status()

        data = resp.json()
        return (
            f"Task {data['task_id']} aborted. "
            f"PID {data.get('pid', '?')} received {data['detail']}."
        )


# ── Web Screenshot + Target Profile ─────────────────────────────────────────


@mcp.tool()
async def web_screenshot(target: str) -> str:
    """
    Capture a screenshot of a web page and build a Target Profile.

    Returns a JSON object containing:
    - screenshot: base64-encoded PNG data URI
    - page_title: the <title> of the page
    - server_headers: HTTP response headers from the server
    - detected_cms: any CMS fingerprints found in the DOM

    Args:
        target: Full URL to profile (e.g. https://example.com).
    """
    from selenium import webdriver
    from selenium.webdriver.chromium.options import ChromiumOptions as ChromeOptions

    profile: dict = {
        "url": target,
        "page_title": None,
        "server_headers": {},
        "detected_cms": [],
        "screenshot": None,
    }

    try:
        async with httpx.AsyncClient(
            timeout=15.0, follow_redirects=True, verify=False
        ) as client:
            head_resp = await client.head(target)
            profile["server_headers"] = dict(head_resp.headers)
    except Exception:
        pass

    options = ChromeOptions()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1920,1080")

    driver = webdriver.Remote(
        command_executor=f"{SELENIUM_URL}/wd/hub",
        options=options,
    )
    try:
        driver.set_page_load_timeout(30)
        driver.get(target)
        await asyncio.sleep(2)

        profile["page_title"] = driver.title or None
        screenshot_b64 = driver.get_screenshot_as_base64()
        profile["screenshot"] = f"data:image/png;base64,{screenshot_b64}"

        page_source = driver.page_source
        profile["detected_cms"] = _detect_cms(page_source)
    finally:
        driver.quit()

    return json.dumps(profile, indent=2, default=str)


_CMS_SIGNATURES = [
    ("WordPress", re.compile(r'wp-content|wp-includes|/wp-json/', re.IGNORECASE)),
    ("Joomla", re.compile(r'/media/jui/|com_content|Joomla!', re.IGNORECASE)),
    ("Drupal", re.compile(r'Drupal\.settings|drupal\.js|/sites/default/', re.IGNORECASE)),
    ("Shopify", re.compile(r'cdn\.shopify\.com|Shopify\.theme', re.IGNORECASE)),
    ("Wix", re.compile(r'wix\.com|X-Wix-', re.IGNORECASE)),
    ("Squarespace", re.compile(r'squarespace\.com|squarespace-cdn', re.IGNORECASE)),
    ("Ghost", re.compile(r'ghost\.org|content/themes/|ghost-', re.IGNORECASE)),
    ("Webflow", re.compile(r'webflow\.com|wf-page', re.IGNORECASE)),
    ("Adobe Experience Manager", re.compile(r'/etc\.clientlibs/|/content/dam/', re.IGNORECASE)),
    ("Next.js", re.compile(r'__NEXT_DATA__|/_next/', re.IGNORECASE)),
    ("Nuxt.js", re.compile(r'__NUXT__|/_nuxt/', re.IGNORECASE)),
]


def _detect_cms(page_source: str) -> list[str]:
    """Scan page source for known CMS fingerprints."""
    detected = []
    for name, pattern in _CMS_SIGNATURES:
        if pattern.search(page_source):
            detected.append(name)
    return detected


if __name__ == "__main__":
    mcp.run()
