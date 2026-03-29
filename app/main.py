"""
Kinetic Strike Engine — FastAPI core.

Exposes /execute to launch validated pentesting tools as async subprocesses,
/tasks/{id} to poll status, /tasks/{id}/logs to stream output, and
DELETE /execute/{task_id} as an emergency kill switch.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse

from app.models import (
    AbortResponse,
    ExecuteRequest,
    ExecuteResponse,
    TaskStatusResponse,
)
from app.task_manager import TaskManager
from app.validator import load_tool_config, validate_target, validate_tool_and_flags

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("kinetic.api")

task_manager: TaskManager


@asynccontextmanager
async def lifespan(app: FastAPI):
    global task_manager
    task_manager = TaskManager(max_concurrent=8)
    logger.info("Kinetic Strike Engine online.")
    yield
    logger.info("Kinetic Strike Engine shutting down.")


app = FastAPI(
    title="Kinetic Strike Engine",
    description="Multi-threaded offensive tool gateway for authorized security testing.",
    version="0.2.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health():
    return {"status": "ok", "engine": "kinetic", "version": "0.2.0"}


@app.post("/execute", response_model=ExecuteResponse)
async def execute(req: ExecuteRequest):
    """
    Launch a security tool against a target.

    Automatically injects structured-output flags (JSON/XML) when the tool
    supports it, so results can be parsed into dictionaries.
    """
    # Validate target string.
    target_err = validate_target(req.target)
    if target_err:
        raise HTTPException(status_code=422, detail=target_err)

    # Validate tool + flags and resolve the full argument list.
    resolved_flags, flag_err = validate_tool_and_flags(req.tool, req.flags)
    if flag_err:
        raise HTTPException(status_code=422, detail=flag_err)

    # Build the final argv.
    args = resolved_flags + [req.target]

    # Detect structured output support from tool YAML config.
    structured_path: str | None = None
    structured_fmt: str | None = None
    config = load_tool_config(req.tool)
    if config and "structured_output" in config:
        so = config["structured_output"]
        # Generate a task-scoped output path.
        import uuid

        task_hint = uuid.uuid4().hex[:12]
        out_path = so["path"].replace("{task_id}", task_hint)
        structured_path = out_path
        structured_fmt = so["format"]

        # Inject the structured-output flag and path into args.
        args = [so["flag"], out_path] + so.get("extra_flags", []) + args

    task_id = await task_manager.submit(
        tool=req.tool,
        args=args,
        target=req.target,
        structured_output_path=structured_path,
        structured_output_format=structured_fmt,
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
