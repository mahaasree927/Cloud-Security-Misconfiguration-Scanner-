"""Data model shared by every check and report."""
from dataclasses import dataclass, asdict

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


@dataclass
class Finding:
    check_id: str        # e.g. "S3-001"
    category: str        # IAM | Storage | Network | Encryption | Logging
    severity: str        # CRITICAL | HIGH | MEDIUM | LOW
    resource: str        # what is misconfigured
    title: str           # short problem statement
    description: str     # why it matters
    remediation: str     # how to fix it

    def to_dict(self):
        return asdict(self)
