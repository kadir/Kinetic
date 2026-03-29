"""
Kinetic Strike Engine — FastAPI core.

Exposes /execute for tool dispatch, /workspace/* for repo lifecycle,
/tasks/* for status polling, and DELETE /execute/{id} as the kill switch.

v0.3.0: Workspace Manager, KiteRunner, renamed tool surface.
"""

from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse

from app.models import (
    AbortResponse,
    CloneRequest,
    ExecuteRequest,
    ExecuteResponse,
    FileEntry,
    FileListResponse,
    TaskStatusResponse,
    WorkspaceResponse,
)
from app.task_manager import TaskManager
from app.validator import (
    load_tool_config,
    validate_path_target,
    validate_target,
    validate_tool_and_flags,
)
from app.workspace import WorkspaceManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("kinetic.api")

task_manager: TaskManager
workspace_manager: WorkspaceManager


@asynccontextmanager
async def lifespan(app: FastAPI):
    global task_manager, workspace_manager
    task_manager = TaskManager(max_concurrent=8)
    workspace_manager = WorkspaceManager()
    workspace_manager.start_cleanup_loop()
    logger.info("Kinetic Strike Engine online.")
    yield
    await workspace_manager.stop()
    logger.info("Kinetic Strike Engine shutting down.")


app = FastAPI(
    title="Kinetic Strike Engine",
    description="Multi-threaded offensive tool gateway for authorized security testing.",
    version="0.3.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health():
    return {"status": "ok", "engine": "kinetic", "version": "0.3.0"}


# ── Workspace Management ────────────────────────────────────────────────────


@app.post("/workspace/clone", response_model=WorkspaceResponse)
async def clone_workspace(req: CloneRequest):
    """
    Clone a git repo into an isolated workspace directory.

    The workspace is assigned a unique ID and auto-deleted after TTL expires.
    """
    entry = await workspace_manager.clone(repo_url=req.repo_url, ttl=req.ttl)
    return WorkspaceResponse(
        workspace_id=entry.workspace_id,
        repo_url=entry.repo_url,
        path=entry.path,
        status=entry.clone_status,
        ttl=entry.ttl,
        error=entry.error,
    )


@app.get("/workspace/{workspace_id}", response_model=WorkspaceResponse)
async def get_workspace(workspace_id: str):
    """Get the status of a workspace."""
    entry = workspace_manager.get(workspace_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return WorkspaceResponse(
        workspace_id=entry.workspace_id,
        repo_url=entry.repo_url,
        path=entry.path,
        status=entry.clone_status,
        ttl=entry.ttl,
        error=entry.error,
    )


@app.get("/workspace/{workspace_id}/files", response_model=FileListResponse)
async def list_workspace_files(
    workspace_id: str,
    subpath: str = "",
    max_depth: int = 3,
):
    """
    List files inside a cloned workspace.

    Returns a tree of files and directories (excluding .git internals).
    """
    files = workspace_manager.list_files(
        workspace_id, subpath=subpath, max_depth=max_depth,
    )
    if files is None:
        raise HTTPException(
            status_code=404,
            detail="Workspace not found or not ready",
        )
    return FileListResponse(
        workspace_id=workspace_id,
        total_files=len([f for f in files if f["type"] == "file"]),
        files=[FileEntry(**f) for f in files],
    )


@app.delete("/workspace/{workspace_id}")
async def delete_workspace(workspace_id: str):
    """Delete a workspace and all its files."""
    deleted = await workspace_manager.delete(workspace_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return {"workspace_id": workspace_id, "status": "deleted"}


@app.get("/workspace")
async def list_workspaces():
    """List all active (non-deleted) workspaces."""
    return [
        WorkspaceResponse(
            workspace_id=ws.workspace_id,
            repo_url=ws.repo_url,
            path=ws.path,
            status=ws.clone_status,
            ttl=ws.ttl,
            error=ws.error,
        )
        for ws in workspace_manager.list_all()
    ]


# ── Tool Execution ──────────────────────────────────────────────────────────


@app.post("/execute", response_model=ExecuteResponse)
async def execute(req: ExecuteRequest):
    """
    Launch a security tool against a target.

    Automatically injects structured-output flags (JSON/XML) when the tool
    supports it. For path-mode tools (semgrep, gitleaks), the target is
    treated as a filesystem path under the workspace directory.
    """
    config = load_tool_config(req.tool)
    if not config:
        raise HTTPException(status_code=422, detail=f"Unknown tool: {req.tool!r}")

    is_path_mode = config.get("target_mode") == "path"

    # Validate target based on mode.
    if is_path_mode:
        target_err = validate_path_target(req.target)
    else:
        target_err = validate_target(req.target)
    if target_err:
        raise HTTPException(status_code=422, detail=target_err)

    # Validate flags against allowlist.
    resolved_flags, flag_err = validate_tool_and_flags(req.tool, req.flags)
    if flag_err:
        raise HTTPException(status_code=422, detail=flag_err)

    # Build argv — resolved_flags include defaults.
    # If the tool specifies a target_flag (e.g. "--source" for gitleaks),
    # inject it as a flag pair instead of a positional argument.
    target_flag = config.get("target_flag")
    if target_flag:
        args = resolved_flags + [target_flag, req.target]
    else:
        args = resolved_flags + [req.target]

    # Detect structured output support.
    structured_path: str | None = None
    structured_fmt: str | None = None
    structured_via_stdout: bool = False
    task_hint = uuid.uuid4().hex[:12]

    if "structured_output" in config:
        so = config["structured_output"]
        out_path = so["path"].replace("{task_id}", task_hint)
        structured_path = out_path
        structured_fmt = so["format"]
        structured_via_stdout = so.get("output_via_stdout", False)

        if structured_via_stdout:
            # Flag goes into args but output is captured from stdout, not a file.
            args = [so["flag"]] + so.get("extra_flags", []) + args
        else:
            # Inject flag + output path into args.
            inject = [so["flag"]]
            extra = so.get("extra_flags", [])

            # Some tools split flag and path (e.g. gitleaks --report-format json
            # --report-path /path), others combine them (e.g. -oX /path).
            # If extra_flags exist, the path goes after them.
            if extra:
                inject.append(so["format"])
                inject.extend(extra)
                inject.append(out_path)
            else:
                inject.append(out_path)

            args = inject + args

    # For path-mode tools, run in the target directory.
    cwd: str | None = None
    if is_path_mode:
        cwd = req.target

    task_id = await task_manager.submit(
        tool=req.tool,
        args=args,
        target=req.target,
        cwd=cwd,
        structured_output_path=structured_path,
        structured_output_format=structured_fmt,
        structured_via_stdout=structured_via_stdout,
    )

    return ExecuteResponse(
        task_id=task_id,
        tool=req.tool,
        target=req.target,
        status="submitted",
    )


# ── Emergency Brake ──────────────────────────────────────────────────────────


@app.delete("/execute/{task_id}", response_model=AbortResponse)
async def abort_task(task_id: str, force: bool = False):
    """
    Emergency kill switch — terminate or force-kill a running task.

    Query params:
        force: If true, send SIGKILL instead of SIGTERM.
    """
    pid = task_manager.get_pid(task_id)
    result = task_manager.get_status(task_id)
    if not result:
        raise HTTPException(status_code=404, detail="Task not found")

    if result.status.value not in ("running", "pending"):
        raise HTTPException(
            status_code=409,
            detail=f"Task is already {result.status.value}",
        )

    if force:
        killed = await task_manager.kill(task_id)
        verb = "SIGKILL"
    else:
        killed = await task_manager.cancel(task_id)
        verb = "SIGTERM"

    if not killed:
        raise HTTPException(
            status_code=500,
            detail="Failed to terminate process",
        )

    logger.warning("Task %s aborted via %s (PID %s)", task_id, verb, pid)
    return AbortResponse(
        task_id=task_id,
        pid=pid,
        status="aborted",
        detail=f"Sent {verb} to PID {pid}",
    )


# ── Task Status & Logs ──────────────────────────────────────────────────────


@app.get("/tasks/{task_id}", response_model=TaskStatusResponse)
async def get_task(task_id: str):
    """Poll a task's current status, including parsed structured output."""
    result = task_manager.get_status(task_id)
    if not result:
        raise HTTPException(status_code=404, detail="Task not found")
    return TaskStatusResponse(
        task_id=result.task_id,
        tool=result.tool,
        status=result.status.value,
        return_code=result.return_code,
        log_file=result.log_file,
        duration=result.duration,
        error=result.error,
        parsed_output=result.parsed_output,
    )


@app.get("/tasks/{task_id}/logs")
async def get_task_logs(task_id: str):
    """Return the raw stdout/stderr log for a task."""
    result = task_manager.get_status(task_id)
    if not result:
        raise HTTPException(status_code=404, detail="Task not found")
    if not result.log_file:
        raise HTTPException(status_code=404, detail="No log file yet")

    log_path = Path(result.log_file)
    if not log_path.is_file():
        raise HTTPException(status_code=404, detail="Log file not found on disk")

    return PlainTextResponse(log_path.read_text(errors="replace"))


@app.get("/tasks")
async def list_tasks():
    """List all tracked tasks."""
    return [
        TaskStatusResponse(
            task_id=r.task_id,
            tool=r.tool,
            status=r.status.value,
            return_code=r.return_code,
            log_file=r.log_file,
            duration=r.duration,
            error=r.error,
            parsed_output=r.parsed_output,
        )
        for r in task_manager.list_tasks()
    ]


@app.post("/tasks/{task_id}/cancel")
async def cancel_task(task_id: str):
    """Cancel a running task (graceful SIGTERM)."""
    cancelled = await task_manager.cancel(task_id)
    if not cancelled:
        raise HTTPException(
            status_code=409, detail="Task is not running or does not exist"
        )
    return {"task_id": task_id, "status": "cancelled"}
