"""
Kinetic TaskManager — async subprocess orchestrator.

Spawns CLI tools (nmap, nuclei, ffuf, etc.) via asyncio.create_subprocess_exec,
streams stdout/stderr in real time, tracks task lifecycle, and parses
structured output (JSON/XML) when the tool supports it.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("kinetic.task_manager")

LOG_DIR = Path("/tmp/kinetic/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class TaskResult:
    task_id: str
    tool: str
    status: TaskStatus
    return_code: Optional[int] = None
    log_file: Optional[str] = None
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    error: Optional[str] = None
    parsed_output: Optional[dict | list] = None

    @property
    def duration(self) -> Optional[float]:
        if self.started_at and self.finished_at:
            return round(self.finished_at - self.started_at, 3)
        return None


@dataclass
class _TaskEntry:
    task_id: str
    tool: str
    args: list[str]
    target: str
    structured_output_path: Optional[Path] = None
    structured_output_format: Optional[str] = None
    status: TaskStatus = TaskStatus.PENDING
    process: Optional[asyncio.subprocess.Process] = None
    log_file: Optional[Path] = None
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    error: Optional[str] = None
    parsed_output: Optional[dict | list] = None


def _xml_to_dict(element: ET.Element) -> dict:
    """Recursively convert an XML ElementTree node to a dict."""
    result: dict[str, Any] = {}
    if element.attrib:
        result["@attributes"] = dict(element.attrib)
    if element.text and element.text.strip():
        result["@text"] = element.text.strip()

    for child in element:
        child_dict = _xml_to_dict(child)
        tag = child.tag
        if tag in result:
            existing = result[tag]
            if not isinstance(existing, list):
                result[tag] = [existing]
            result[tag].append(child_dict)
        else:
            result[tag] = child_dict
    return result


def _parse_structured_file(path: Path, fmt: str) -> dict | list | None:
    """Parse a structured output file into a Python object."""
    if not path.is_file():
        return None

    raw = path.read_text(errors="replace").strip()
    if not raw:
        return None

    if fmt == "json":
        return json.loads(raw)

    if fmt == "jsonl":
        lines = [line for line in raw.splitlines() if line.strip()]
        return [json.loads(line) for line in lines]

    if fmt == "xml":
        root = ET.fromstring(raw)
        return _xml_to_dict(root)

    return None


class TaskManager:
    """Manages concurrent subprocess-based tool executions."""

    def __init__(self, max_concurrent: int = 8) -> None:
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._tasks: dict[str, _TaskEntry] = {}

    async def submit(
        self,
        tool: str,
        args: list[str],
        target: str,
        structured_output_path: str | None = None,
        structured_output_format: str | None = None,
    ) -> str:
        """Submit a tool for background execution. Returns a task_id."""
        task_id = uuid.uuid4().hex[:12]
        entry = _TaskEntry(
            task_id=task_id,
            tool=tool,
            args=args,
            target=target,
            structured_output_path=Path(structured_output_path) if structured_output_path else None,
            structured_output_format=structured_output_format,
        )
        self._tasks[task_id] = entry
        asyncio.create_task(self._run(entry))
        logger.info("Task %s submitted: %s -> %s", task_id, tool, target)
        return task_id

    async def _run(self, entry: _TaskEntry) -> None:
        async with self._semaphore:
            entry.status = TaskStatus.RUNNING
            entry.started_at = time.time()
            log_path = LOG_DIR / f"{entry.task_id}.log"
            entry.log_file = log_path

            try:
                proc = await asyncio.create_subprocess_exec(
                    entry.tool,
                    *entry.args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                entry.process = proc

                with open(log_path, "wb") as fh:
                    async for chunk in proc.stdout:
                        fh.write(chunk)
                        fh.flush()

                await proc.wait()
                entry.finished_at = time.time()

                if proc.returncode == 0:
                    entry.status = TaskStatus.COMPLETED
                else:
                    entry.status = TaskStatus.FAILED
                    entry.error = f"exit code {proc.returncode}"

                # Attempt to parse structured output if configured.
                if entry.structured_output_path and entry.structured_output_format:
                    try:
                        entry.parsed_output = _parse_structured_file(
                            entry.structured_output_path,
                            entry.structured_output_format,
                        )
                    except Exception as parse_err:
                        logger.warning(
                            "Task %s: structured output parse failed: %s",
                            entry.task_id,
                            parse_err,
                        )

            except FileNotFoundError:
                entry.status = TaskStatus.FAILED
                entry.finished_at = time.time()
                entry.error = f"tool binary not found: {entry.tool}"
                logger.error("Task %s failed: %s", entry.task_id, entry.error)

            except Exception as exc:
                entry.status = TaskStatus.FAILED
                entry.finished_at = time.time()
                entry.error = str(exc)
                logger.exception("Task %s crashed", entry.task_id)

    async def cancel(self, task_id: str) -> bool:
        """Cancel a running task via SIGTERM. Returns True if sent."""
        entry = self._tasks.get(task_id)
        if not entry or entry.status != TaskStatus.RUNNING or not entry.process:
            return False
        entry.process.terminate()
        entry.status = TaskStatus.CANCELLED
        entry.finished_at = time.time()
        return True

    async def kill(self, task_id: str) -> bool:
        """Force-kill a running task via SIGKILL. Returns True if sent."""
        entry = self._tasks.get(task_id)
        if not entry or entry.status != TaskStatus.RUNNING or not entry.process:
            return False
        entry.process.kill()
        entry.status = TaskStatus.CANCELLED
        entry.finished_at = time.time()
        return True

    def get_pid(self, task_id: str) -> int | None:
        """Return the PID of a running task, or None."""
        entry = self._tasks.get(task_id)
        if entry and entry.process:
            return entry.process.pid
        return None

    def get_status(self, task_id: str) -> Optional[TaskResult]:
        entry = self._tasks.get(task_id)
        if not entry:
            return None
        return TaskResult(
            task_id=entry.task_id,
            tool=entry.tool,
            status=entry.status,
            return_code=entry.process.returncode if entry.process else None,
            log_file=str(entry.log_file) if entry.log_file else None,
            started_at=entry.started_at,
            finished_at=entry.finished_at,
            error=entry.error,
            parsed_output=entry.parsed_output,
        )

    def list_tasks(self) -> list[TaskResult]:
        return [self.get_status(tid) for tid in self._tasks]
