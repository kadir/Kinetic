"""
Kinetic MCP Gate — FastMCP server exposing pentesting tools to Claude.

Each tool dispatches work to the Strike Engine API and polls for results.
v0.2.5: code_audit, enumerate_subdomains, find_hidden_params, scan_secrets.
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
WORKSPACE = os.getenv("KINETIC_WORKSPACE", "/tmp/kinetic/workspace")
POLL_INTERVAL = 2.0
POLL_TIMEOUT = 300.0

mcp = FastMCP(
    "Kinetic Gate",
    instructions=(
        "Kinetic is an offensive security MCP gateway for authorized pentesting. "
        "Tool selection guidance:\n"
        "- When given a file path or git repo URL → use code_audit or scan_secrets\n"
        "- When given a root domain (e.g. example.com) → use enumerate_subdomains\n"
        "- When given a URL → use vuln_scan, find_hidden_params, or web_screenshot\n"
        "- When given an IP or CIDR → use port_scan\n"
        "- To stop any running scan → use abort_scan"
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


async def _clone_repo(repo_url: str) -> str:
    """Clone a git repo into the workspace. Returns the local path."""
    repo_name = repo_url.rstrip("/").split("/")[-1].removesuffix(".git")
    dest = os.path.join(WORKSPACE, repo_name)

    if os.path.isdir(dest):
        # Pull latest instead of re-cloning.
        proc = await asyncio.create_subprocess_exec(
            "git", "-C", dest, "pull", "--ff-only",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        await proc.wait()
        return dest

    proc = await asyncio.create_subprocess_exec(
        "git", "clone", "--depth", "1", repo_url, dest,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    await proc.wait()
    if proc.returncode != 0:
        output = await proc.stdout.read()
        raise RuntimeError(f"git clone failed: {output.decode(errors='replace')}")
    return dest


def _format_result(result: dict) -> str:
    """Return parsed JSON if available, else raw output."""
    parsed = result.get("parsed_output")
    if parsed:
        return json.dumps(parsed, indent=2, default=str)
    return result.get("raw_output", "No output.")


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
async def code_audit(
    path: str,
    ruleset: str = "p/default",
    severity: str = "",
) -> str:
    """
    Run a Semgrep static analysis scan on a codebase.

    Accepts a local directory path (under /tmp/kinetic/workspace) or a git
    repo URL (which will be cloned automatically).

    Args:
        path: Filesystem path to scan, or a git repo URL to clone and scan.
        ruleset: Semgrep ruleset (e.g. "p/default", "p/owasp-top-ten", "p/ci").
        severity: Filter by severity (e.g. "ERROR", "WARNING").
    """
    # If path looks like a URL, clone it first.
    scan_path = path
    if path.startswith("https://") or path.startswith("git@"):
        scan_path = await _clone_repo(path)

    flags = ["--config", ruleset]
    if severity:
        flags.extend(["--severity", severity])

    result = await _execute_and_wait("semgrep", scan_path, flags)
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


# ── Subdomain Enumeration (Subfinder) ───────────────────────────────────────


@mcp.tool()
async def enumerate_subdomains(
    domain: str,
    recursive: bool = False,
) -> str:
    """
    Enumerate subdomains for a root domain using passive sources.

    Use this tool when given a root domain like example.com.

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
        summary = {
            "domain": domain,
            "total_subdomains": len(subdomains),
            "subdomains": subdomains,
        }
        return json.dumps(summary, indent=2)
    return result.get("raw_output") or "No subdomains found."


# ── Hidden Parameter Discovery (Arjun) ──────────────────────────────────────


@mcp.tool()
async def find_hidden_params(
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


# ── Secret Scanning (Gitleaks) ──────────────────────────────────────────────


@mcp.tool()
async def scan_secrets(
    path: str,
    no_git: bool = False,
) -> str:
    """
    Scan a repository or directory for leaked secrets and credentials.

    Accepts a local directory path or a git repo URL.

    Args:
        path: Filesystem path to scan, or a git repo URL to clone and scan.
        no_git: If true, scan files without requiring a git repository.
    """
    scan_path = path
    if path.startswith("https://") or path.startswith("git@"):
        scan_path = await _clone_repo(path)

    flags = []
    if no_git:
        flags.append("--no-git")

    result = await _execute_and_wait("gitleaks", scan_path, flags)

    # Gitleaks exits with code 1 when leaks are found (not an error).
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
        summary = {
            "total_leaks": len(leaks),
            "leaks": leaks,
        }
        return json.dumps(summary, indent=2)

    if result["status"] == "failed" and result.get("return_code") == 1:
        # Gitleaks found leaks but structured parse failed — return raw.
        return result.get("raw_output") or "Leaks detected (see raw output)."

    if result["status"] == "failed":
        return f"Scan failed: {result.get('error', 'unknown error')}\n{result['raw_output']}"

    return "No secrets detected."


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
    from selenium.webdriver.chrome.options import Options as ChromeOptions

    profile: dict = {
        "url": target,
        "page_title": None,
        "server_headers": {},
        "detected_cms": [],
        "screenshot": None,
    }

    # Fetch server headers via httpx first (lightweight, no browser needed).
    try:
        async with httpx.AsyncClient(
            timeout=15.0, follow_redirects=True, verify=False
        ) as client:
            head_resp = await client.head(target)
            profile["server_headers"] = dict(head_resp.headers)
    except Exception:
        pass

    # Browser session for screenshot + DOM inspection.
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
