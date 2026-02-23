"""AC-3.3–3.4: Basic auth injection tests."""

import base64

from auth_injection_proxy.injection.basic import inject_basic
from tests.conftest import make_flow


class TestBasicInjection:
    def test_injects_basic_header(self):
        """AC-3.3: Basic auth sets correct Authorization header."""
        flow = make_flow("https://jira.example.com/api")
        secrets = inject_basic(flow, "user", "pass")
        expected = base64.b64encode(b"user:pass").decode()
        assert flow.request.headers["Authorization"] == f"Basic {expected}"
        assert expected in secrets

    def test_special_characters(self):
        """AC-3.4: Special characters encoded correctly."""
        flow = make_flow("https://jira.example.com/api")
        inject_basic(flow, "user@org", "p@ss:word")
        expected = base64.b64encode(b"user@org:p@ss:word").decode()
        assert flow.request.headers["Authorization"] == f"Basic {expected}"
