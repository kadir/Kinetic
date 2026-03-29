"""
Kinetic MCP Gate — FastMCP server exposing pentesting tools to Claude.

Each tool dispatches work to the Strike Engine API and polls for results.
v0.2.0: Structured output parsing, abort_scan, target profiling.
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
        "Kinetic is an offensive security MCP gateway. "
        "Use these tools for authorized vulnerability research and pentesting only."
    ),
)


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
                # Fetch raw logs as fallback.
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
    flags = ["-u", target, "-severity", severity]
    if tags:
        flags.extend(["-tags", tags])

    result = await _execute_and_wait("nuclei", target, flags)
    if result["status"] == "failed":
        return f"Scan failed: {result.get('error', 'unknown error')}\n{result['raw_output']}"

    parsed = result.get("parsed_output")
    if parsed:
        return json.dumps(parsed, indent=2, default=str)
    return result.get("raw_output") or "No vulnerabilities found."


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
        pass  # Headers are best-effort; continue with browser.

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

        # Give JS time to render.
        await asyncio.sleep(2)

        # Page title.
        profile["page_title"] = driver.title or None

        # Screenshot.
        screenshot_b64 = driver.get_screenshot_as_base64()
        profile["screenshot"] = f"data:image/png;base64,{screenshot_b64}"

        # CMS detection via DOM inspection.
        page_source = driver.page_source
        profile["detected_cms"] = _detect_cms(page_source)

    finally:
        driver.quit()

    return json.dumps(profile, indent=2, default=str)


# CMS detection patterns: (name, regex applied to page source).
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
