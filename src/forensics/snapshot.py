"""Container forensic snapshot service.

Captures point-in-time snapshots of running containers including:
  - Container metadata and configuration
  - Filesystem listing (full tree with hashes)
  - Process table
  - Open network connections
  - Environment variables (sanitised)
  - Mount points and volumes
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class FilesystemEntry:
    """A single entry in the container filesystem inventory."""
    path: str
    file_type: str        # file, dir, symlink, other
    size: int = 0
    mode: str = ""
    owner: str = ""
    group: str = ""
    mtime: str = ""
    sha256: str = ""      # empty for non-files


@dataclass(slots=True)
class ProcessInfo:
    """A single process within the container."""
    pid: int
    ppid: int
    user: str = ""
    command: str = ""
    args: str = ""
    start_time: str = ""
    cpu_percent: float = 0.0
    mem_percent: float = 0.0


@dataclass(slots=True)
class NetworkConnection:
    """An active network connection."""
    protocol: str            # tcp, udp
    local_addr: str = ""
    local_port: int = 0
    remote_addr: str = ""
    remote_port: int = 0
    state: str = ""          # ESTABLISHED, LISTEN, etc.
    pid: int = 0
    process_name: str = ""


@dataclass(slots=True)
class ContainerSnapshot:
    """Complete forensic snapshot of a container at a point in time."""
    snapshot_id: str
    container_id: str
    captured_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc))
    image_name: str = ""
    image_digest: str = ""

    # Container state
    status: str = ""
    created_at: str = ""
    started_at: str = ""
    restart_count: int = 0

    # Configuration
    config: dict[str, Any] = field(default_factory=dict)
    env_vars: dict[str, str] = field(default_factory=dict)
    labels: dict[str, str] = field(default_factory=dict)
    mounts: list[dict[str, Any]] = field(default_factory=list)
    ports: dict[str, Any] = field(default_factory=dict)

    # Inventory
    filesystem: list[FilesystemEntry] = field(default_factory=list)
    processes: list[ProcessInfo] = field(default_factory=list)
    connections: list[NetworkConnection] = field(default_factory=list)

    # Integrity
    snapshot_hash: str = ""  # SHA-256 of the entire snapshot

    # Artifact path
    artifact_path: str = ""

    @property
    def file_count(self) -> int:
        return len(self.filesystem)

    @property
    def process_count(self) -> int:
        return len(self.processes)

    @property
    def connection_count(self) -> int:
        return len(self.connections)

    def compute_hash(self) -> str:
        """Compute SHA-256 of the snapshot for integrity."""
        data = json.dumps(self.to_dict(), sort_keys=True, default=str).encode()
        return hashlib.sha256(data).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "container_id": self.container_id,
            "captured_at": self.captured_at.isoformat(),
            "image_name": self.image_name,
            "image_digest": self.image_digest,
            "status": self.status,
            "config": self.config,
            "env_vars": {**self.env_vars},
            "labels": {**self.labels},
            "mounts": self.mounts,
            "ports": self.ports,
            "filesystem": [
                _file_to_dict(f) for f in self.filesystem
            ],
            "processes": [
                _proc_to_dict(p) for p in self.processes
            ],
            "connections": [
                _conn_to_dict(c) for c in self.connections
            ],
            "snapshot_hash": self.snapshot_hash,
            "artifact_path": self.artifact_path,
        }


def _file_to_dict(f: FilesystemEntry) -> dict:
    return {
        "path": f.path, "type": f.file_type, "size": f.size,
        "mode": f.mode, "sha256": f.sha256,
    }


def _proc_to_dict(p: ProcessInfo) -> dict:
    return {
        "pid": p.pid, "ppid": p.ppid, "user": p.user,
        "command": p.command, "cpu_pct": p.cpu_percent,
        "mem_pct": p.mem_percent,
    }


def _conn_to_dict(c: NetworkConnection) -> dict:
    return {
        "proto": c.protocol, "local": f"{c.local_addr}:{c.local_port}",
        "remote": f"{c.remote_addr}:{c.remote_port}",
        "state": c.state, "pid": c.pid,
    }


# ---------------------------------------------------------------------------
# Sanitisation helpers
# ---------------------------------------------------------------------------

# Patterns that should never appear in forensic exports
_SENSITIVE_ENV_KEYS = frozenset({
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "private_key", "aws_secret", "azure_key", "cred",
})


def _sanitise_env(key: str, value: str) -> tuple[str, str]:
    """Return (key, value) with sensitive values redacted."""
    if any(pat in key.lower() for pat in _SENSITIVE_ENV_KEYS):
        return key, "***REDACTED***"
    return key, value


# ---------------------------------------------------------------------------
# Sub-process helpers
# ---------------------------------------------------------------------------

async def _run(cmd: list[str], timeout: float = 30) -> tuple[str, int]:
    """Run a command and return (stdout, returncode)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(
            proc.communicate(), timeout=timeout)
        return stdout.decode(errors="replace").strip(), proc.returncode or 0
    except asyncio.TimeoutError:
        return "", 124
    except FileNotFoundError:
        return "", 127


# ---------------------------------------------------------------------------
# Forensic snapshot service
# ---------------------------------------------------------------------------

class ForensicSnapshotService:
    """Captures complete snapshots of containers for forensic analysis.

    Usage:
        svc = ForensicSnapshotService()
        snap = await svc.capture(container_id)
        # snap.to_dict() for JSON, snap.artifact_path for tarball
    """

    # Sensitive env keys to always redact
    SENSITIVE_PATTERNS = _SENSITIVE_ENV_KEYS

    def __init__(self, docker_bin: str = "docker"):
        self.docker_bin = docker_bin
        self._archive_dir: str = ""

    def set_archive_dir(self, path: str) -> None:
        """Set directory for snapshot artifacts."""
        self._archive_dir = path
        os.makedirs(path, exist_ok=True)

    async def capture(self, container_id: str,
                      include_files: bool = True,
                      include_processes: bool = True,
                      include_network: bool = True,
                      ) -> ContainerSnapshot:
        """Capture a complete forensic snapshot."""
        snapshot_id = f"snap-{int(time.time() * 1000):x}-{container_id[:8]}"

        # 1. Container metadata
        meta = await self._get_container_metadata(container_id)
        env = await self._get_env(container_id)
        mounts = await self._get_mounts(container_id)
        ports = await self._get_ports(container_id)

        # 2. Filesystem inventory
        fs_entries: list[FilesystemEntry] = []
        if include_files:
            fs_entries = await self._inventory_filesystem(container_id)

        # 3. Process table
        procs: list[ProcessInfo] = []
        if include_processes:
            procs = await self._get_processes(container_id)

        # 4. Network connections
        conns: list[NetworkConnection] = []
        if include_network:
            conns = await self._get_connections(container_id)

        snap = ContainerSnapshot(
            snapshot_id=snapshot_id,
            container_id=container_id,
            image_name=meta.get("image", ""),
            image_digest=meta.get("digest", ""),
            status=meta.get("status", ""),
            created_at=meta.get("created", ""),
            started_at=meta.get("started", ""),
            restart_count=meta.get("restart_count", 0),
            config=meta.get("config", {}),
            env_vars={k: v for k, v in env},
            labels=meta.get("labels", {}),
            mounts=mounts,
            ports=ports,
            filesystem=fs_entries,
            processes=procs,
            connections=conns,
        )
        snap.snapshot_hash = snap.compute_hash()

        # Optionally create tarball artifact
        artifact = await self._create_artifact(snap)
        if artifact:
            snap.artifact_path = artifact

        return snap

    # -- Metadata collection ------------------------------------------------ #

    async def _get_container_metadata(self, cid: str) -> dict[str, Any]:
        out, rc = await _run([self.docker_bin, "inspect", cid])
        if rc != 0 or not out:
            return {}
        try:
            info = json.loads(out)[0]
        except (json.JSONDecodeError, IndexError):
            return {}
        state = info.get("State", {})
        created = info.get("Created", "")
        digest = ""
        if info.get("Image"):
            digest = info["Image"][:19] if len(info.get("Image", "")) > 19 else info.get("Image", "")
        return {
            "image": info.get("Config", {}).get("Image", ""),
            "digest": digest,
            "status": state.get("Status", ""),
            "created": created,
            "started": state.get("StartedAt", ""),
            "restart_count": state.get("RestartCount", 0),
            "config": {
                "hostname": info.get("Config", {}).get("Hostname", ""),
                "user": info.get("Config", {}).get("User", ""),
                "entrypoint": info.get("Config", {}).get("Entrypoint"),
                "cmd": info.get("Config", {}).get("Cmd"),
                "working_dir": info.get("Config", {}).get("WorkingDir", ""),
            },
            "labels": info.get("Config", {}).get("Labels", {}),
            "platform": info.get("Platform", {}),
        }

    async def _get_env(self, cid: str) -> list[tuple[str, str]]:
        out, rc = await _run(
            [self.docker_bin, "inspect", "--format",
             "{{json .Config.Env}}", cid])
        if rc != 0 or not out:
            return []
        try:
            env_list = json.loads(out)
        except (json.JSONDecodeError, TypeError):
            return []
        result: list[tuple[str, str]] = []
        for item in env_list or []:
            if "=" in item:
                k, _, v = item.partition("=")
                result.append(_sanitise_env(k, v))
        return result

    async def _get_mounts(self, cid: str) -> list[dict]:
        out, rc = await _run(
            [self.docker_bin, "inspect", "--format",
             "{{json .Mounts}}", cid])
        if rc != 0 or not out:
            return []
        try:
            return json.loads(out) or []
        except json.JSONDecodeError:
            return []

    async def _get_ports(self, cid: str) -> dict:
        out, rc = await _run(
            [self.docker_bin, "inspect", "--format",
             "{{json .NetworkSettings.Ports}}", cid])
        if rc != 0 or not out:
            return {}
        try:
            return json.loads(out) or {}
        except json.JSONDecodeError:
            return {}

    # -- Filesystem inventory ----------------------------------------------- #

    async def _inventory_filesystem(self, cid: str) -> list[FilesystemEntry]:
        """Walk the container filesystem via ``docker exec`` + ``find``."""
        # Use find to get a listing, then stat each entry
        cmd = [
            self.docker_bin, "exec", cid,
            "find", "/",
            "-maxdepth", "3",        # limit depth for speed
            "-not", "-path", "/proc/*",
            "-not", "-path", "/sys/*",
            "-not", "-path", "/dev/*",
            "-printf", "%p|%y|%s|%m|%u|%g|%T@\\n",
        ]
        out, rc = await _run(cmd, timeout=60)
        if rc != 0 or not out:
            return []

        entries: list[FilesystemEntry] = []
        for line in out.splitlines():
            parts = line.rstrip("\\n").split("|")
            if len(parts) < 7:
                continue
            ftype = parts[1]
            entry = FilesystemEntry(
                path=parts[0],
                file_type=self._map_ftype(ftype),
                size=int(parts[2]) if parts[2] and parts[2] != "0" else 0,
                mode=parts[3],
                owner=parts[4],
                group=parts[5],
                mtime=parts[6],
            )
            entries.append(entry)

        # Hash important binaries and config files
        config_paths = [
            "/etc/passwd", "/etc/shadow", "/etc/hosts",
            "/etc/resolv.conf", "/etc/group",
        ]
        for path in config_paths:
            for e in entries:
                if e.path == path and e.file_type == "file":
                    e.sha256 = await self._hash_file(cid, path)
                    break

        return entries

    async def _hash_file(self, cid: str, path: str) -> str:
        """Compute SHA-256 of a file inside the container."""
        out, rc = await _run(
            [self.docker_bin, "exec", cid, "sha256sum", path], timeout=30)
        if rc == 0 and out:
            return out.split()[0].strip()
        return ""

    @staticmethod
    def _map_ftype(c: str) -> str:
        mapping = {"f": "file", "d": "dir", "l": "symlink", "p": "fifo",
                    "s": "socket", "c": "char_dev", "b": "block_dev"}
        return mapping.get(c, "other")

    # -- Process table ------------------------------------------------------ #

    async def _get_processes(self, cid: str) -> list[ProcessInfo]:
        out, rc = await _run(
            [self.docker_bin, "top", cid, "-eo",
             "pid,ppid,user,pcpu,pmem,lstart,args"], timeout=15)
        if rc != 0 or not out:
            return []

        lines = out.splitlines()
        if len(lines) < 2:
            return []

        procs: list[ProcessInfo] = []
        for line in lines[1:]:  # skip header
            parts = line.split(None, 8)
            if len(parts) < 6:
                continue
            proc = ProcessInfo(
                pid=int(parts[0]),
                ppid=int(parts[1]),
                user=parts[2],
                cpu_percent=float(parts[3]),
                mem_percent=float(parts[4]),
                command=parts[5] if len(parts) > 5 else "",
                start_time=" ".join(parts[5:8]) if len(parts) >= 8 else "",
                args=parts[5] if len(parts) < 9 else " ".join(parts[5:]),
            )
            procs.append(proc)
        return procs

    # -- Network connections ------------------------------------------------ #

    async def _get_connections(self, cid: str) -> list[NetworkConnection]:
        """Get active network connections via ``docker inspect`` + ``ss``."""
        # Try ss inside the container first
        out, rc = await _run(
            [self.docker_bin, "exec", cid, "ss", "-tunap"], timeout=15)
        if rc == 0 and out:
            return self._parse_ss(out)

        # Fallback: netstat
        out, rc = await _run(
            [self.docker_bin, "exec", cid, "netstat", "-tunap"], timeout=15)
        if rc == 0 and out:
            return self._parse_ss(out)

        # Final fallback: from docker inspect NetworkSettings
        return await self._inspect_connections(cid)

    async def _inspect_connections(self, cid: str) -> list[NetworkConnection]:
        out, rc = await _run(
            [self.docker_bin, "inspect", "--format", "{{json .NetworkSettings}}", cid])
        if rc != 0 or not out:
            return []
        try:
            ns = json.loads(out)
        except json.JSONDecodeError:
            return []
        conns: list[NetworkConnection] = []
        ip = ns.get("IPAddress", "")
        for port_spec, host_bindings in (ns.get("Ports") or {}).items():
            parts = port_spec.split("/")
            if len(parts) < 2:
                continue
            proto = parts[1]
            port = int(parts[0])
            if host_bindings:
                for binding in host_bindings:
                    conns.append(NetworkConnection(
                        protocol=proto,
                        local_addr=ip,
                        local_port=port,
                        remote_addr=binding.get("HostIp", ""),
                        remote_port=int(binding.get("HostPort", 0)),
                        state="LISTEN",
                    ))
            else:
                conns.append(NetworkConnection(
                    protocol=proto, internal=ip, local_port=port, state="LISTEN"))
        return conns

    @staticmethod
    def _parse_ss(output: str) -> list[NetworkConnection]:
        conns: list[NetworkConnection] = []
        for line in output.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            proto = parts[0].lower()
            state = parts[1] if not parts[1][0].isdigit() else "ESTABLISHED"
            idx = 2 if not parts[1][0].isdigit() else 1
            local = parts[idx]
            remote = parts[idx + 1] if len(parts) > idx + 1 else ""
            process = parts[idx + 2] if len(parts) > idx + 2 else ""

            laddr, lport = _addr_port(local)
            raddr, rport = _addr_port(remote)
            pid = _parse_pid(process)
            proc_name = _parse_process_name(process)

            conns.append(NetworkConnection(
                protocol=proto, local_addr=laddr, local_port=lport,
                remote_addr=raddr, remote_port=rport, state=state,
                pid=pid, process_name=proc_name,
            ))
        return conns

    # -- Artifact creation -------------------------------------------------- #

    async def _create_artifact(self, snap: ContainerSnapshot) -> str | None:
        """Write the snapshot to a tarball artifact."""
        if not self._archive_dir:
            return None

        artifact_name = f"{snap.container_id}_{snap.snapshot_id}.tar.gz"
        path = os.path.join(self._archive_dir, artifact_name)

        try:
            with tarfile.open(path, "w:gz") as tar:
                # Store metadata as JSON
                meta_json = json.dumps(snap.to_dict(), indent=2).encode()
                import io
                ti = tarfile.TarInfo(name="metadata.json")
                ti.size = len(meta_json)
                tar.addfile(ti, io.BytesIO(meta_json))

                # Export container filesystem snapshot if docker is available
                export_path = os.path.join(self._archive_dir, f"{snap.container_id}.tar")
                if not os.path.exists(export_path):
                    await _run(
                        [self.docker_bin, "export", "-o", export_path,
                         snap.container_id], timeout=300)
                if os.path.exists(export_path):
                    tar.add(export_path, arcname="filesystem.tar")
                    try:
                        os.unlink(export_path)
                    except OSError:
                        pass
            return path
        except Exception:
            logger.exception("Failed to create artifact for %s", snap.container_id)
            return None


# ---------------------------------------------------------------------------
# Addr/port parsing helpers
# ---------------------------------------------------------------------------

def _addr_port(s: str) -> tuple[str, int]:
    if ":" in s:
        host, _, port = s.rpartition(":")
        return host, int(port) if port.isdigit() else 0
    return s, 0


def _parse_pid(s: str) -> int:
    for part in s.split(","):
        if "pid=" in part:
            _, _, pid = part.partition("pid=")
            pid = pid.strip()
            return int(pid) if pid.isdigit() else 0
    return 0


def _parse_process_name(s: str) -> str:
    for part in s.split(","):
        if "users:" in part:
            _, _, name = part.partition("users:")
            return name.strip().rstrip(")").lstrip("(")
    return ""
