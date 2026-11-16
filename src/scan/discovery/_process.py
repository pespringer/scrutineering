"""Run a runtime CLI with a timeout, treating a missing binary as no output."""

from __future__ import annotations

import asyncio


async def run_cli(cmd: list[str], *, timeout: float = 15) -> tuple[int, str, str] | None:
    """Return (returncode, stdout, stderr), or None if the binary is missing or times out."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (asyncio.TimeoutError, FileNotFoundError):
        return None
    return proc.returncode or 0, stdout.decode(), stderr.decode()
