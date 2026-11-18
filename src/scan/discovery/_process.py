"""Run a runtime CLI with a timeout, treating a missing binary as no output."""

from __future__ import annotations

import asyncio


class RuntimeUnavailable(Exception):
    """The container runtime could not be listed. Not the same as "nothing is running"."""


def failure(result: tuple[int, str, str] | None, binary: str) -> str | None:
    """Why a runtime CLI call failed, in one line, or None if it succeeded."""
    if result is None:
        return f"{binary} is missing or timed out"
    returncode, _, stderr = result
    if returncode != 0:
        lines = [line.strip() for line in stderr.splitlines() if line.strip()]
        return (lines[0] if lines else f"{binary} exited with {returncode}")[:300]
    return None


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
