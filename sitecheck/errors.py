"""Stable error codes shared with the API contract."""


class CheckError(Exception):
    code = "internal_error"

    def __init__(self, code=None, message="", **detail):
        self.code = code or self.code
        self.message = message or self.code
        self.detail = detail
        super().__init__(f"{self.code}: {self.message}")


class InputRejected(CheckError):
    """Input refused before any job exists (HTTP 4xx in the contract)."""
    code = "invalid_url"


class FetchError(CheckError):
    """Page/job level failure recorded inside a report."""
    code = "connection_failed"


class BudgetExhausted(FetchError):
    code = "request_budget_exhausted"


class DnsBudgetExhausted(FetchError):
    code = "dns_budget_exhausted"


class JobTimeout(FetchError):
    code = "job_timeout"


class TransportError(FetchError):
    """Raised by a transport: fetch_timeout, connection_failed, tls_error."""


class IdempotencyConflict(CheckError):
    code = "idempotency_key_conflict"
