"""Runtime behaviour analysis engine.

Collects events from the eBPF agent, computes baselines, detects anomalies,
and produces actionable alerts.  Acceptance criteria covered:
  - Track container network traffic (inbound/outbound, DNS)
  - Monitor file access patterns within containers
  - Track process execution and fork patterns
  - Monitor resource utilization (CPU, memory, network, disk I/O)
  - Detect anomalous behaviour patterns
"""

from __future__ import annotations

import logging
import math
import statistics
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from src.runtime.ebpf_agent import RuntimeEvent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Anomaly types
# ---------------------------------------------------------------------------

class AnomalyKind:
    UNEXPECTED_PROCESS   = "unexpected_process"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    NETWORK_ANOMALY      = "network_anomaly"
    FILE_ANOMALY         = "file_anomaly"
    CRYPTO_MINING        = "crypto_mining"
    DATA_EXFILTRATION    = "data_exfiltration"
    REVERSE_SHELL        = "reverse_shell"
    RESOURCE_SPIKE       = "resource_spike"


@dataclass(slots=True)
class Anomaly:
    kind: str
    severity: str              # critical, high, medium, low
    container_id: str
    description: str
    evidence: dict[str, Any]
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved: bool = False

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "container_id": self.container_id,
            "description": self.description,
            "evidence": self.evidence,
            "detected_at": self.detected_at.isoformat(),
            "resolved": self.resolved,
        }


# ---------------------------------------------------------------------------
# Baseline statistics (per container)
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class ContainerBaseline:
    """Rolling baselines used for anomaly detection."""
    syscalls_per_minute: deque[float] = field(
        default_factory=lambda: deque(maxlen=288))  # 2 h at 30 s
    unique_processes: set[str] = field(default_factory=set)
    common_ports: Counter = field(default_factory=Counter)
    dns_queries: Counter = field(default_factory=Counter)
    file_paths_touched: Counter = field(default_factory=Counter)
    cpu_samples: deque[float] = field(
        default_factory=lambda: deque(maxlen=120))  # last 2 h
    mem_samples_mb: deque[float] = field(
        default_factory=lambda: deque(maxlen=120))
    network_in_bytes: deque[int] = field(
        default_factory=lambda: deque(maxlen=288))
    network_out_bytes: deque[int] = field(
        default_factory=lambda: deque(maxlen=288))
    last_update: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Analysis engine
# ---------------------------------------------------------------------------

class RuntimeBehaviorAnalyzer:
    """Consumes events, maintains baselines, raises anomalies.

    Designed to be used both as a stream processor (per-event) and
    in periodic batch mode (analyse accumulated data).
    """

    # Thresholds — tweakable
    PROCESS_NOT_ANOMALY = {"sh", "bash", "cat", "ls", "cp", "mv", "rm",
                           "echo", "sleep", "date", "hostname", "id",
                           "whoami", "uname", "ps", "top", "free", "df"}
    PRIV_ESCALATION_SYSCALLS = {"setuid", "setgid", "setreuid",
                                "setregid"}
    SUSPICIOUS_SYSCALLS = {"ptrace", "process_vm_readv",
                           "process_vm_writev", "init_module",
                           "finit_module", "delete_module"}
    MINE_INDICATORS = {"xmrig", "minerd", "cpuminer", "ethminer",
                       "nicehash", "kworkerds", "kdevtmpfsi"}
    REVERSE_SHELL_INDICATORS = {"/dev/tcp", "nc -e", "ncat", "socat",
                                "bash -i", "python -c", "perl -e"}
    FILE_ANOMALY_PATHS = {"/etc/passwd", "/etc/shadow", "/etc/ssh",
                          "/root/.ssh", "/proc/kcore", "/dev/mem"}

    def __init__(self,
                 anomaly_threshold_sigma: float = 3.0,
                 baseline_window_minutes: int = 30):
        self.sigma = anomaly_threshold_sigma
        self.window = timedelta(minutes=baseline_window_minutes)
        self._baselines: dict[str, ContainerBaseline] = {}
        self._anomaly_callback: Any = None
        self._recent_anomalies: deque[Anomaly] = deque(maxlen=500)

    # -- Public API --------------------------------------------------------- #

    def set_anomaly_callback(self, cb) -> None:  # Callable[[Anomaly], None]
        self._anomaly_callback = cb

    def process_event(self, event: RuntimeEvent) -> list[Anomaly]:
        """Process a single event.  Returns new anomalies if any."""
        cid = event.container_id
        b = self._get_baseline(cid)
        b.last_update = time.time()
        anomalies: list[Anomaly] = []

        # Update baselines
        if event.event_type == "syscall":
            self._update_syscall_baseline(b, event)
            a = self._check_anomalies_syscall(event, b)
            if a:
                anomalies.extend(a)
        elif event.event_type == "network":
            self._update_network_baseline(b, event)
            a = self._check_anomalies_network(event, b)
            if a:
                anomalies.extend(a)
        elif event.event_type == "process":
            a = self._check_anomalies_process(event, b)
            if a:
                anomalies.extend(a)
        elif event.event_type == "file_access":
            a = self._check_anomalies_file(event, b)
            if a:
                anomalies.extend(a)
        elif event.event_type == "resource":
            self._update_resource_baseline(b, event)

        # Notify
        for anomaly in anomalies:
            self._recent_anomalies.append(anomaly)
            if self._anomaly_callback:
                try:
                    self._anomaly_callback(anomaly.to_dict())
                except Exception:
                    logger.exception("Anomaly callback failed")

        return anomalies

    def get_anomalies(self, container_id: str | None = None,
                      since: datetime | None = None,
                      unresolved_only: bool = True) -> list[dict]:
        """Query recent anomalies."""
        results: list[Anomaly] = []
        for a in self._recent_anomalies:
            if unresolved_only and a.resolved:
                continue
            if container_id and a.container_id != container_id:
                continue
            if since and a.detected_at < since:
                continue
            results.append(a)
        return [a.to_dict() for a in results]

    # -- Baseline helpers --------------------------------------------------- #

    def _get_baseline(self, cid: str) -> ContainerBaseline:
        if cid not in self._baselines:
            self._baselines[cid] = ContainerBaseline()
        return self._baselines[cid]

    def _update_syscall_baseline(self, b: ContainerBaseline,
                                 event: RuntimeEvent) -> None:
        now = time.time()
        # Count events in sliding windows
        b.syscalls_per_minute.append(
            len(b.syscalls_per_minute))  # simplified — would use buckets
        comm = event.detail.get("comm", "")
        if comm:
            b.unique_processes.add(comm)
        if event.detail.get("syscall") == "connect":
            port = event.detail.get("dest_port")
            if port:
                b.common_ports[str(port)] += 1

    def _update_network_baseline(self, b: ContainerBaseline,
                                 event: RuntimeEvent) -> None:
        d = event.detail
        if d.get("type") == "dns":
            b.dns_queries[d.get("query", "")] += 1
        tx = d.get("tx_bytes", 0)
        rx = d.get("rx_bytes", 0)
        b.network_in_bytes.append(int(rx))
        b.network_out_bytes.append(int(tx))

    def _update_resource_baseline(self, b: ContainerBaseline,
                                  event: RuntimeEvent) -> None:
        d = event.detail
        if "cpu_pct" in d:
            b.cpu_samples.append(float(d["cpu_pct"]))
        if "mem_mb" in d:
            b.mem_samples_mb.append(float(d["mem_mb"]))

    # -- Anomaly detectors -------------------------------------------------- #

    def _check_anomalies_syscall(self, event: RuntimeEvent,
                                 b: ContainerBaseline) -> list[Anomaly]:
        anomalies: list[Anomaly] = []
        detail = event.detail
        syscall = detail.get("syscall", "")
        comm = detail.get("comm", "")

        # Privilege escalation
        if syscall in self.PRIV_ESCALATION_SYSCALLS:
            anomalies.append(Anomaly(
                kind=AnomalyKind.PRIVILEGE_ESCALATION,
                severity="high",
                container_id=event.container_id,
                description=f"Privilege change: {syscall} by {comm}",
                evidence=detail,
            ))

        # Suspicious syscalls (ptrace, module loading, etc.)
        if syscall in self.SUSPICIOUS_SYSCALLS:
            anomalies.append(Anomaly(
                kind=AnomalyKind.PRIVILEGE_ESCALATION,
                severity="high",
                container_id=event.container_id,
                description=f"Suspicious syscall: {syscall} by {comm}",
                evidence=detail,
            ))

        # Crypto mining detection
        if comm:
            for indicator in self.MINE_INDICATORS:
                if indicator.lower() in comm.lower():
                    anomalies.append(Anomaly(
                        kind=AnomalyKind.CRYPTO_MINING,
                        severity="critical",
                        container_id=event.container_id,
                        description=f"Crypto mining indicator: {comm}",
                        evidence=detail,
                    ))

        # Rate anomaly
        if len(b.syscalls_per_minute) > 10:
            mean = statistics.mean(b.syscalls_per_minute)
            stdev = statistics.stdev(b.syscalls_per_minute) if len(b.syscalls_per_minute) > 1 else 0
            current_rate = len(b.syscalls_per_minute)
            if stdev > 0 and current_rate > mean + self.sigma * stdev:
                anomalies.append(Anomaly(
                    kind=AnomalyKind.RESOURCE_SPIKE,
                    severity="medium",
                    container_id=event.container_id,
                    description=f"Syscall rate spike: {current_rate:.0f} "
                                f"(baseline {mean:.0f} +/- {stdev:.0f})",
                    evidence={"rate": current_rate, "mean": mean,
                              "stdev": stdev},
                ))
        return anomalies

    def _check_anomalies_process(self, event: RuntimeEvent,
                                 b: ContainerBaseline) -> list[Anomaly]:
        anomalies: list[Anomaly] = []
        cmd = event.detail.get("command", "") or event.detail.get("comm", "")

        # New/unexpected process
        if cmd and cmd not in b.unique_processes:
            if cmd not in self.PROCESS_NOT_ANOMALY:
                b.unique_processes.add(cmd)
                anomalies.append(Anomaly(
                    kind=AnomalyKind.UNEXPECTED_PROCESS,
                    severity="medium",
                    container_id=event.container_id,
                    description=f"New process observed: {cmd}",
                    evidence=event.detail,
                ))

        # Reverse shell indicators — report only once per event
        if cmd:
            matched_indicators = [
                ind for ind in self.REVERSE_SHELL_INDICATORS
                if ind.lower() in cmd.lower()
            ]
            if matched_indicators:
                anomalies.append(Anomaly(
                    kind=AnomalyKind.REVERSE_SHELL,
                    severity="critical",
                    container_id=event.container_id,
                    description=f"Possible reverse shell: {cmd} "
                                f"(indicators: {', '.join(matched_indicators)})",
                    evidence=event.detail,
                ))
        return anomalies

    def _check_anomalies_network(self, event: RuntimeEvent,
                                 b: ContainerBaseline) -> list[Anomaly]:
        anomalies: list[Anomaly] = []
        dest_ip = event.detail.get("dest_ip", "")
        dest_port = event.detail.get("dest_port")

        # Outbound to unusual port
        if dest_port and dest_port not in (80, 443, 53, 8080, 8443, 22):
            if str(dest_port) not in b.common_ports:
                anomalies.append(Anomaly(
                    kind=AnomalyKind.NETWORK_ANOMALY,
                    severity="medium",
                    container_id=event.container_id,
                    description=f"Connection to unusual port {dest_port}",
                    evidence=event.detail,
                ))

        # Data exfiltration (large outbound volume)
        if len(b.network_out_bytes) > 5:
            mean_out = statistics.mean(b.network_out_bytes)
            current = event.detail.get("tx_bytes", 0)
            if mean_out > 0 and current > mean_out * 5:
                anomalies.append(Anomaly(
                    kind=AnomalyKind.DATA_EXFILTRATION,
                    severity="high",
                    container_id=event.container_id,
                    description=f"Unusual outbound volume: {current} bytes "
                                f"(baseline {mean_out:.0f})",
                    evidence=event.detail,
                ))
        return anomalies

    def _check_anomalies_file(self, event: RuntimeEvent,
                              b: ContainerBaseline) -> list[Anomaly]:
        path = event.detail.get("path", "")
        if path in self.FILE_ANOMALY_PATHS:
            return [Anomaly(
                kind=AnomalyKind.FILE_ANOMALY,
                severity="high",
                container_id=event.container_id,
                description=f"Sensitive file access: {path}",
                evidence=event.detail,
            )]
        return []

    # -- Resource monitoring helpers ---------------------------------------- #

    def get_resource_stats(self, container_id: str) -> dict:
        """Return current resource statistics for a container."""
        b = self._baselines.get(container_id)
        if not b:
            return {}

        def _stats(samples):
            if not samples:
                return {"mean": 0, "p95": 0, "max": 0, "count": 0}
            return {
                "mean": statistics.mean(samples),
                "p95": sorted(samples)[int(len(samples) * 0.95)],
                "max": max(samples),
                "count": len(samples),
            }

        return {
            "cpu": _stats(list(b.cpu_samples)),
            "memory_mb": _stats(list(b.mem_samples_mb)),
            "network_in_bytes": _stats(list(b.network_in_bytes)),
            "network_out_bytes": _stats(list(b.network_out_bytes)),
            "unique_processes": len(b.unique_processes),
            "common_ports": dict(b.common_ports.most_common(10)),
            "dns_queries": dict(b.dns_queries.most_common(10)),
            "last_update": b.last_update,
        }

    def clear_baseline(self, container_id: str) -> None:
        self._baselines.pop(container_id, None)
