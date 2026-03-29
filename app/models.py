"""Pydantic request/response models for the Kinetic API."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


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
