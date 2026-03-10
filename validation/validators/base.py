from __future__ import annotations

from abc import ABC, abstractmethod

from ..http_client import SimpleHttpClient
from ..models import NormalizedFinding, ValidationResult


class BaseValidator(ABC):
    """
    Base class for all vulnerability-class validators.
    """

    vuln_class: str = "Other"

    @abstractmethod
    def validate(self, finding: NormalizedFinding, client: SimpleHttpClient) -> ValidationResult:
        raise NotImplementedError


