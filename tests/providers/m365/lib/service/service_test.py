from unittest.mock import MagicMock, patch

import pytest
from msgraph.generated.models.o_data_errors.o_data_error import ODataError

from prowler.providers.m365.lib.service.service import M365Service


class TestM365ServiceErrorTracking:
    """Tests for the generic API error tracking in M365Service."""

    def _make_service(self):
        """Create an M365Service with mocked provider."""
        with patch.object(M365Service, "__init__", lambda self, *a, **kw: None):
            svc = M365Service.__new__(M365Service)
            svc._api_errors = {}
        return svc

    def test_api_error_for_returns_none_when_no_error(self):
        svc = self._make_service()
        assert svc.api_error_for("users") is None

    def test_collect_api_error_stores_message(self):
        svc = self._make_service()
        svc._collect_api_error("users", "some error")
        assert svc.api_error_for("users") == "some error"

    def test_api_error_for_returns_none_for_different_attribute(self):
        svc = self._make_service()
        svc._collect_api_error("users", "some error")
        assert svc.api_error_for("groups") is None

    def test_multiple_errors_tracked_independently(self):
        svc = self._make_service()
        svc._collect_api_error("users", "error A")
        svc._collect_api_error("groups", "error B")
        assert svc.api_error_for("users") == "error A"
        assert svc.api_error_for("groups") == "error B"

    def test_is_permission_error_with_odata_403(self):
        error = ODataError()
        error.__dict__["response_status_code"] = 403
        assert M365Service._is_permission_error(error) is True

    def test_is_permission_error_with_authorization_denied(self):
        error = ODataError()
        inner = MagicMock()
        inner.code = "Authorization_RequestDenied"
        error.error = inner
        assert M365Service._is_permission_error(error) is True

    def test_is_permission_error_with_ms_graph_permission_missing(self):
        error = ODataError()
        inner = MagicMock()
        inner.code = "Authentication_MSGraphPermissionMissing"
        error.error = inner
        assert M365Service._is_permission_error(error) is True

    def test_is_permission_error_returns_false_for_generic_exception(self):
        assert M365Service._is_permission_error(ValueError("unrelated")) is False

    def test_is_permission_error_returns_false_for_non_403_odata(self):
        error = ODataError()
        error.__dict__["response_status_code"] = 400
        inner = MagicMock()
        inner.code = "BadRequest"
        error.error = inner
        assert M365Service._is_permission_error(error) is False
