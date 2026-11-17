import hashlib
from dataclasses import dataclass, field
from typing import Callable, Protocol


@dataclass
class ScanRequest:
    scan_id: str
    url: str
    hostname: str
    port: int
    include_subdomains: bool
    mode: str                      # passive | active_safe


@dataclass
class FindingDTO:
    rule_id: str
    title: str
    severity: str                  # info | low | medium | high | critical
    url: str
    confidence: str | None = None
    method: str | None = None
    param: str | None = None
    cwe_id: int | None = None
    description: str | None = None
    solution: str | None = None
    reference: str | None = None
    evidence: str | None = None

    def fingerprint(self) -> str:
        return hashlib.sha256(f"{self.rule_id}|{self.url}|{self.method}|{self.param}".encode()).hexdigest()


@dataclass
class ScanOutcome:
    findings: list[FindingDTO] = field(default_factory=list)
    cancelled: bool = False
    stats: dict = field(default_factory=dict)


class Scanner(Protocol):
    """Interfaz común: añadir `nuclei` = implementar esta clase y registrarla en worker/tasks.py."""
    def run(self, req: ScanRequest, should_cancel: Callable[[], bool]) -> ScanOutcome: ...
    def cleanup(self) -> None: ...
