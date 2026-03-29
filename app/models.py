"""Pydantic request/response models for the Kinetic API."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Execute ──────────────────────────────────────────────────────────────────


class ExecuteRequest(BaseModel):
    """Request body for POST /execute."""

    tool: str = Field(
        ...,
        description="Tool to run (e.g. 'nmap', 'nuclei', 'ffuf', 'curl').",
        pattern=r"^[a-z][a-z0-9_-]*$",
    )
    target: str = Field(
        ...,
        description="Target host, URL, or IP address.",
        min_length=1,
        max_length=253,
    )
    flags: list[str] = Field(
        default_factory=list,
        description="Additional CLI flags (validated against allowlist).",
    )


class ExecuteResponse(BaseModel):
    task_id: str
    tool: str
    target: str
    status: str


class TaskStatusResponse(BaseModel):
    task_id: str
    tool: str
    status: str
    return_code: Optional[int] = None
    log_file: Optional[str] = None
    duration: Optional[float] = None
    error: Optional[str] = None
    parsed_output: Optional[Any] = None


class AbortResponse(BaseModel):
    task_id: str
    pid: Optional[int] = None
    status: str
    detail: str


# ── Workspace ────────────────────────────────────────────────────────────────


class CloneRequest(BaseModel):
    """Request body for POST /workspace/clone."""

    repo_url: str = Field(
        ...,
        description="Git repository URL to clone.",
        pattern=r"^(https://|git@).+$",
    )
    ttl: int = Field(
        default=3600,
        ge=60,
        le=86400,
        description="Time-to-live in seconds before auto-cleanup (60-86400).",
    )


class WorkspaceResponse(BaseModel):
    workspace_id: str
    repo_url: str
    path: str
    status: str
    ttl: int
    error: Optional[str] = None


class FileEntry(BaseModel):
    path: str
    type: str
    size: Optional[int] = None


class FileListResponse(BaseModel):
    workspace_id: str
    total_files: int
    files: list[FileEntry]
