"""
Kinetic Workspace Manager — git clone lifecycle, TTL cleanup, file listing.

Clones repositories into isolated /tmp/kinetic/workspace/{workspace_id}/
directories, tracks metadata, and garbage-collects expired workspaces.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger("kinetic.workspace")

WORKSPACE_ROOT = Path("/tmp/kinetic/workspace")
WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)

DEFAULT_TTL = 3600  # 1 hour


@dataclass
class WorkspaceEntry:
    workspace_id: str
    repo_url: str
    path: str
    created_at: float
    ttl: int = DEFAULT_TTL
    clone_status: str = "cloning"  # cloning, ready, failed, deleted
    error: Optional[str] = None

    @property
    def expires_at(self) -> float:
        return self.created_at + self.ttl

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at


class WorkspaceManager:
    """Manages cloned repository workspaces with TTL-based cleanup."""

    def __init__(self) -> None:
        self._workspaces: dict[str, WorkspaceEntry] = {}
        self._cleanup_task: Optional[asyncio.Task] = None

    def start_cleanup_loop(self) -> None:
        """Start the background TTL reaper."""
        self._cleanup_task = asyncio.create_task(self._reaper())

    async def stop(self) -> None:
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

    async def _reaper(self) -> None:
        """Periodically purge expired workspaces."""
        while True:
            await asyncio.sleep(60)
            now = time.time()
            expired = [
                ws for ws in self._workspaces.values()
                if ws.is_expired and ws.clone_status != "deleted"
            ]
            for ws in expired:
                logger.info(
                    "Reaping expired workspace %s (%s)",
                    ws.workspace_id, ws.repo_url,
                )
                await self.delete(ws.workspace_id)

    async def clone(self, repo_url: str, ttl: int = DEFAULT_TTL) -> WorkspaceEntry:
        """Clone a repo into a new workspace directory."""
        workspace_id = uuid.uuid4().hex[:12]
        dest = WORKSPACE_ROOT / workspace_id
        dest.mkdir(parents=True, exist_ok=True)

        entry = WorkspaceEntry(
            workspace_id=workspace_id,
            repo_url=repo_url,
            path=str(dest),
            created_at=time.time(),
            ttl=ttl,
        )
        self._workspaces[workspace_id] = entry

        # Run git clone in background.
        asyncio.create_task(self._do_clone(entry, dest))
        return entry

    async def _do_clone(self, entry: WorkspaceEntry, dest: Path) -> None:
        try:
            proc = await asyncio.create_subprocess_exec(
                "git", "clone", "--depth", "1", entry.repo_url, str(dest),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout, _ = await proc.communicate()

            if proc.returncode == 0:
                entry.clone_status = "ready"
                logger.info("Workspace %s cloned: %s", entry.workspace_id, entry.repo_url)
            else:
                entry.clone_status = "failed"
                entry.error = stdout.decode(errors="replace").strip()
                logger.error("Workspace %s clone failed: %s", entry.workspace_id, entry.error)
        except Exception as exc:
            entry.clone_status = "failed"
            entry.error = str(exc)
            logger.exception("Workspace %s clone crashed", entry.workspace_id)

    async def delete(self, workspace_id: str) -> bool:
        """Delete a workspace and its files from disk."""
        entry = self._workspaces.get(workspace_id)
        if not entry:
            return False

        ws_path = Path(entry.path)
        if ws_path.exists() and ws_path.is_relative_to(WORKSPACE_ROOT):
            shutil.rmtree(ws_path, ignore_errors=True)

        entry.clone_status = "deleted"
        logger.info("Workspace %s deleted", workspace_id)
        return True

    def get(self, workspace_id: str) -> Optional[WorkspaceEntry]:
        return self._workspaces.get(workspace_id)

    def list_all(self) -> list[WorkspaceEntry]:
        return [
            ws for ws in self._workspaces.values()
            if ws.clone_status != "deleted"
        ]

    def list_files(
        self,
        workspace_id: str,
        subpath: str = "",
        max_depth: int = 3,
    ) -> list[dict] | None:
        """
        List files in a workspace directory tree.

        Returns a flat list of {path, type, size} dicts, or None if the
        workspace doesn't exist.
        """
        entry = self._workspaces.get(workspace_id)
        if not entry or entry.clone_status != "ready":
            return None

        base = Path(entry.path)
        if subpath:
            base = base / subpath

        # Validate no traversal.
        if not base.resolve().is_relative_to(WORKSPACE_ROOT):
            return None
        if not base.is_dir():
            return None

        results: list[dict] = []
        self._walk(base, base, 0, max_depth, results)
        return results

    def _walk(
        self,
        root: Path,
        current: Path,
        depth: int,
        max_depth: int,
        results: list[dict],
    ) -> None:
        if depth > max_depth:
            return
        try:
            entries = sorted(current.iterdir(), key=lambda p: (p.is_file(), p.name))
        except PermissionError:
            return

        for item in entries:
            # Skip .git internals — they're noise.
            if item.name == ".git":
                continue

            relative = str(item.relative_to(root))
            if item.is_dir():
                results.append({"path": relative + "/", "type": "dir", "size": None})
                self._walk(root, item, depth + 1, max_depth, results)
            else:
                try:
                    size = item.stat().st_size
                except OSError:
                    size = None
                results.append({"path": relative, "type": "file", "size": size})
