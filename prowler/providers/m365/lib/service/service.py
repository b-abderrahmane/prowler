from typing import Optional

from msgraph import GraphServiceClient
from msgraph.generated.models.o_data_errors.o_data_error import ODataError

from prowler.lib.logger import logger
from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell
from prowler.providers.m365.m365_provider import M365Provider


class M365Service:
    """Base class for Microsoft 365 service clients.

    Provides a shared Graph API client, PowerShell session, and a generic
    mechanism for tracking permission errors encountered during data fetching.

    Subclass services store the data they fetch as instance attributes.  When a
    fetch fails because the service principal lacks a required Graph API
    permission, the service records the error via :meth:`_collect_api_error` so
    that downstream checks can detect degraded data instead of silently
    consuming empty defaults.

    Checks should call :meth:`api_error_for` with the attribute name they
    depend on (e.g. ``entra_client.api_error_for("users")``) and, if a
    non-None string is returned, emit a single descriptive FAIL rather than
    iterating over the empty/default data.
    """

    # Map ODataError codes that indicate insufficient permissions.
    _PERMISSION_DENIED_CODES = frozenset(
        {
            "Authorization_RequestDenied",
            "Authentication_MSGraphPermissionMissing",
        }
    )

    def __init__(
        self,
        provider: M365Provider,
    ):
        self.client = GraphServiceClient(credentials=provider.session)
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config

        # Maps attribute name → human-readable error message.
        # Populated by _collect_api_error during data fetching.
        self._api_errors: dict[str, str] = {}

        # Initialize PowerShell client only if credentials are available
        self.powershell = (
            M365PowerShell(provider.credentials, provider.identity)
            if provider.credentials and provider.identity
            else None
        )

    # ------------------------------------------------------------------
    # Error tracking helpers
    # ------------------------------------------------------------------

    def api_error_for(self, attribute: str) -> Optional[str]:
        """Return the error message for *attribute*, or ``None`` if the data
        was fetched successfully.

        Checks should call this before consuming service data::

            if error := entra_client.api_error_for("users"):
                report.status = "FAIL"
                report.status_extended = f"Cannot verify ...: {error}"
                return findings
        """
        return self._api_errors.get(attribute)

    def _collect_api_error(self, attribute: str, message: str) -> None:
        """Record that *attribute* could not be populated due to *message*."""
        self._api_errors[attribute] = message
        logger.error(f"{self.__class__.__name__}: {attribute}: {message}")

    @classmethod
    def _is_permission_error(cls, error: Exception) -> bool:
        """Return True if *error* indicates a missing Graph API permission."""
        if isinstance(error, ODataError):
            code = getattr(error.error, "code", None) if error.error else None
            if code in cls._PERMISSION_DENIED_CODES:
                return True
            if error.__dict__.get("response_status_code", None) == 403:
                return True
        return False
