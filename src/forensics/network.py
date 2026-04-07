"""Network traffic capture and logging for container forensics.

Captures:
  - Active connections (periodic snapshots)
  - Traffic flow logs (via conntrack or docker stats)
  - DNS queries (via container logs or proxy)
  - Unusual outbound patterns
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class NetworkFlowRecord:
    """A single network flow record."""
    timestamp: float = field(default_factory=time.time)
    container_id: str = ""
    protocol: str = ""             # tcp, udp, icmp
    src_addr: str = ""
    src_port: int = 0
    dst_addr: str = ""
    dst_port: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0
    duration: float = 0.0
    state: str = ""                # ESTABLISHED, CLOSE_WAIT, etc.
    is_internal: bool = False
    geo_info: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "container_id": self.container_id,
            "protocol": self.protocol,
            "src": f"{self.src_addr}:{self.src_port}",
            "dst": f"{self.dst_addr}:{self.dst_port}",
            "bytes_sent": self.bytes_sent,
            "bytes_recv": self.bytes_recv,
            "packets_sent": self.packets_sent,
            "packets_recv": self.packets_recv,
            "duration": self.duration,
            "state": self.state,
            "is_internal": self.is_internal,
            "geo_info": self.geo_info,
        }


@dataclass(slots=True)
class DNSQueryLog:
    """A logged DNS query."""
    timestamp: float = field(default_factory=time.time)
    container_id: str = ""
    query_name: str = ""
    query_type: str = "A"
    response_code: str = ""
    response_ip: str = ""
    ttl: int = 0

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "container_id": self.container_id,
            "query": self.query_name,
            "type": self.query_type,
            "rcode": self.response_code,
            "answer": self.response_ip,
            "ttl": self.ttl,
        }


# Private/internal IP prefixes
_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "169.254.",
    "fd", "::1",
)


def _is_internal(addr: str) -> bool:
    return any(addr.startswith(p) for p in _PRIVATE_PREFIXES)


# ---------------------------------------------------------------------------
# Network capture service
# ---------------------------------------------------------------------------

class NetworkCaptureService:
    """Captures and logs network activity for containers.

    Usage:
        svc = NetworkCaptureService()
        flows = await svc.capture_flows(container_id)
        svc.log_flow(flow_record)
    """

    def __init__(self, docker_bin: str = "docker", max_flows: int = 10_000):
        self.docker_bin = docker_bin
        self._flows: list[NetworkFlowRecord] = []
        self._dns_log: list[DNSQueryLog] = []
        self._max_flows = max_flows

    async def capture_flows(self, container_id: str) -> list[NetworkFlowRecord]:
        """Capture current network flows for a container."""
        flows = await self._capture_ss(container_id)
        if not flows:
            flows = await self._capture_inspect(container_id)

        for f in flows:
            f.is_internal = _is_internal(f.dst_addr)
        return flows

    async def _capture_ss(self, cid: str) -> list[NetworkFlowRecord]:
        """Capture via ss/netstat inside the container."""
        out = await _run([self.docker_bin, "exec", cid,
                           "ss", "-tunap", "-o"])
        if out:
            return self._parse_ss_flows(out, cid)

        out = await _run([self.docker_bin, "exec", cid,
                           "netstat", "-tunap"])
        if out:
            return self._parse_netstat(out, cid)
        return []

    async def _capture_inspect(self, cid: str) -> list[NetworkFlowRecord]:
        """Capture from Docker inspect (port mappings only)."""
        out = await _run([self.docker_bin, "inspect", "--format",
                           "{{json .NetworkSettings}}", cid])
        if not out:
            return []
        try:
            ns = json.loads(out)
        except json.JSONDecodeError:
            return []
        flows: list[NetworkFlowRecord] = []
        ip = ns.get("IPAddress", "")
        for port_spec, bindings in (ns.get("Ports") or {}).items():
            parts = port_spec.split("/")
            if len(parts) < 2:
                continue
            proto = parts[1]
            port = int(parts[0]) if parts[0].isdigit() else 0
            if bindings:
                for b in bindings:
                    flows.append(NetworkFlowRecord(
                        container_id=cid, protocol=proto,
                        src_addr=b.get("HostIp", "0.0.0.0"),
                        src_port=int(b.get("HostPort", 0)),
                        dst_addr=ip, dst_port=port,
                        state="LISTEN",
                    ))
        return flows

    def _parse_ss_flows(self, output: str, cid: str) -> list[NetworkFlowRecord]:
        flows: list[NetworkFlowRecord] = []
        for line in output.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            proto = parts[0]
            state = parts[1] if not parts[1][0].isdigit() else "ESTABLISHED"
            idx = 2 if not parts[1][0].isdigit() else 1
            local = parts[idx]
            remote = parts[idx + 1] if len(parts) > idx + 1 else ""

            laddr, lport = _addr_port(local)
            raddr, rport = _addr_port(remote)
            flows.append(NetworkFlowRecord(
                container_id=cid, protocol=proto,
                src_addr=laddr, src_port=lport,
                dst_addr=raddr, dst_port=rport,
                state=state, is_internal=_is_internal(raddr),
            ))
        return flows

    def _parse_netstat(self, output: str, cid: str) -> list[NetworkFlowRecord]:
        flows: list[NetworkFlowRecord] = []
        for line in output.splitlines()[2:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            proto = parts[0]
            local = parts[3]
            remote = parts[4]
            state = parts[5] if len(parts) > 5 else ""
            laddr, lport = _addr_port(local)
            raddr, rport = _addr_port(remote)
            flows.append(NetworkFlowRecord(
                container_id=cid, protocol=proto,
                src_addr=laddr, src_port=lport,
                dst_addr=raddr, dst_port=rport,
                state=state, is_internal=_is_internal(raddr),
            ))
        return flows

    # -- Logging ------------------------------------------------------------ #

    def log_flow(self, flow: NetworkFlowRecord) -> None:
        """Log a network flow record."""
        self._flows.append(flow)
        if len(self._flows) > self._max_flows:
            self._flows = self._flows[-self._max_flows:]

    def log_dns(self, entry: DNSQueryLog) -> None:
        """Log a DNS query."""
        self._dns_log.append(entry)
        if len(self._dns_log) > self._max_flows:
            self._dns_log = self._dns_log[-self._max_flows:]

    # -- Queries ------------------------------------------------------------ #

    def get_flows(self, container_id: str | None = None,
                  external_only: bool = False,
                  limit: int = 100) -> list[dict]:
        results = []
        for f in self._flows:
            if container_id and f.container_id != container_id:
                continue
            if external_only and f.is_internal:
                continue
            results.append(f.to_dict())
            if len(results) >= limit:
                break
        return results

    def get_dns_log(self, container_id: str | None = None,
                    limit: int = 100) -> list[dict]:
        results = []
        for d in self._dns_log:
            if container_id and d.container_id != container_id:
                continue
            results.append(d.to_dict())
            if len(results) >= limit:
                break
        return results

    def export_json(self) -> dict[str, Any]:
        """Export all captured data as JSON."""
        return {
            "flows": [f.to_dict() for f in self._flows],
            "dns": [d.to_dict() for d in self._dns_log],
            "total_flows": len(self._flows),
            "total_dns": len(self._dns_log),
        }

    def clear(self) -> None:
        self._flows.clear()
        self._dns_log.clear()

    # -- Anomaly detection helpers ------------------------------------------ #

    def detect_unusual_ports(self, container_id: str) -> list[dict]:
        """Find connections to non-standard ports."""
        standard = {22, 53, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017}
        unusual = []
        for f in self._flows:
            if (f.container_id == container_id
                    and f.dst_port not in standard
                    and not f.is_internal):
                unusual.append(f.to_dict())
        return unusual


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _run(cmd: list[str], timeout: float = 15) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
        stdout, _ = await asyncio.wait_for(
            proc.communicate(), timeout=timeout)
        return stdout.decode(errors="replace").strip()
    except (asyncio.TimeoutError, FileNotFoundError):
        return ""


def _addr_port(s: str) -> tuple[str, int]:
    if ":" in s:
        host, _, port = s.rpartition(":")
        return host, int(port) if port.isdigit() else 0
    return s, 0
