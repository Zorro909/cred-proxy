"""AC-7: Secret masking tests."""

from auth_injection_proxy.matching.models import (
    BasicAuth,
    BearerAuth,
    CredentialRule,
    ExternalScriptAuth,
    HeaderAuth,
    OAuth2ClientCredentialsAuth,
    QueryParamAuth,
)
from auth_injection_proxy.store.masking import mask_rule, mask_secret


class TestMaskSecret:
    def test_long_token(self):
        """AC-7.1: sk-proj-abc123xyz789 → sk-***789"""
        result = mask_secret("sk-proj-abc123xyz789")
        assert result == "sk-***789"

    def test_short_value(self):
        assert mask_secret("ab") == "***"

    def test_no_separator(self):
        result = mask_secret("abcdefghij")
        assert result.endswith("hij")
        assert "***" in result


class TestMaskRule:
    def test_bearer_masked(self):
        """AC-7.1: Bearer token masked."""
        rule = CredentialRule(
            id="r1", domain="d.com", auth=BearerAuth(type="bearer", token="sk-secret-token")
        )
        masked = mask_rule(rule)
        assert masked["auth"]["token"] != "sk-secret-token"
        assert "***" in masked["auth"]["token"]

    def test_basic_password_masked(self):
        """AC-7.2: Password masked, username shown."""
        rule = CredentialRule(
            id="r1",
            domain="d.com",
            auth=BasicAuth(type="basic", username="user", password="secret"),
        )
        masked = mask_rule(rule)
        assert masked["auth"]["username"] == "user"
        assert masked["auth"]["password"] == "***"

    def test_header_value_masked(self):
        """AC-7.3: Header value masked."""
        rule = CredentialRule(
            id="r1",
            domain="d.com",
            auth=HeaderAuth(type="header", header_name="X-Key", header_value="secret-val"),
        )
        masked = mask_rule(rule)
        assert masked["auth"]["header_name"] == "X-Key"
        assert "***" in masked["auth"]["header_value"]

    def test_oauth2_secret_masked(self):
        """AC-7.4: client_secret masked, client_id and token_url shown."""
        rule = CredentialRule(
            id="r1",
            domain="d.com",
            auth=OAuth2ClientCredentialsAuth(
                type="oauth2_client_credentials",
                token_url="https://auth.com/token",
                client_id="my-id",
                client_secret="my-secret",
            ),
        )
        masked = mask_rule(rule)
        assert masked["auth"]["client_id"] == "my-id"
        assert masked["auth"]["token_url"] == "https://auth.com/token"
        assert "***" in masked["auth"]["client_secret"]

    def test_query_param_masked(self):
        """AC-7.5: Query param value masked."""
        rule = CredentialRule(
            id="r1",
            domain="d.com",
            auth=QueryParamAuth(type="query_param", param_name="key", param_value="secret123"),
        )
        masked = mask_rule(rule)
        assert masked["auth"]["param_name"] == "key"
        assert "***" in masked["auth"]["param_value"]

    def test_external_script_env_masked(self):
        """External script env values masked."""
        rule = CredentialRule(
            id="r1",
            domain="d.com",
            auth=ExternalScriptAuth(
                type="external_script",
                script="./token.sh",
                env={"API_KEY": "secret-key", "APP_ID": "12345"},
            ),
        )
        masked = mask_rule(rule)
        assert masked["auth"]["script"] == "./token.sh"
        assert masked["auth"]["env"] == {"API_KEY": "***", "APP_ID": "***"}

    def test_external_script_empty_env(self):
        """External script with no env → empty dict preserved."""
        rule = CredentialRule(
            id="r1",
            domain="d.com",
            auth=ExternalScriptAuth(
                type="external_script",
                script="./token.sh",
            ),
        )
        masked = mask_rule(rule)
        assert masked["auth"]["env"] == {}
