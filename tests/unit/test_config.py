"""AC-1.2–1.5, AC-15: Config parsing tests."""

import pytest

from auth_injection_proxy.config import load_config


class TestLoadConfig:
    def test_valid_config(self, sample_yaml):
        """AC-1.2: Full config parses correctly."""
        config = load_config(sample_yaml)
        assert config.proxy.listen_port == 8080
        assert config.proxy.mgmt_port == 8081
        assert config.proxy.credential_request_ttl == 900
        assert len(config.credentials) == 2

    def test_empty_credentials(self, tmp_path):
        """AC-1.3: Empty credentials starts fine."""
        path = tmp_path / "config.yaml"
        path.write_text("proxy:\n  listen_port: 8080\ncredentials: []\n")
        config = load_config(str(path))
        assert config.credentials == []

    def test_missing_config_file(self, tmp_path):
        """AC-1.4: Missing file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_config(str(tmp_path / "nonexistent.yaml"))

    def test_malformed_yaml(self, tmp_path):
        """AC-1.5: Malformed YAML raises error."""
        path = tmp_path / "bad.yaml"
        path.write_text("credentials:\n  - {invalid yaml {{{\n")
        with pytest.raises(Exception):
            load_config(str(path))

    def test_duplicate_ids(self, tmp_path):
        """AC-5.2: Duplicate IDs raise error."""
        path = tmp_path / "dupes.yaml"
        path.write_text("""credentials:
  - id: "same"
    domain: "a.com"
    auth:
      type: bearer
      token: "t1"
  - id: "same"
    domain: "b.com"
    auth:
      type: bearer
      token: "t2"
""")
        with pytest.raises(ValueError, match="Duplicate"):
            load_config(str(path))

    def test_custom_ttl(self, tmp_path):
        """AC-15.1: Custom TTL parsed."""
        path = tmp_path / "config.yaml"
        path.write_text("proxy:\n  credential_request_ttl: 60\ncredentials: []\n")
        config = load_config(str(path))
        assert config.proxy.credential_request_ttl == 60

    def test_default_ttl(self, tmp_path):
        """AC-15.2: Default TTL is 900."""
        path = tmp_path / "config.yaml"
        path.write_text("proxy: {}\ncredentials: []\n")
        config = load_config(str(path))
        assert config.proxy.credential_request_ttl == 900

    def test_custom_ports(self, tmp_path):
        """AC-15.3: Custom ports parsed."""
        path = tmp_path / "config.yaml"
        path.write_text("proxy:\n  listen_port: 9090\n  mgmt_port: 9091\ncredentials: []\n")
        config = load_config(str(path))
        assert config.proxy.listen_port == 9090
        assert config.proxy.mgmt_port == 9091

    def test_defaults_when_minimal(self, tmp_path):
        """Defaults applied for missing sections."""
        path = tmp_path / "config.yaml"
        path.write_text("{}\n")
        config = load_config(str(path))
        assert config.proxy.listen_port == 8080
        assert config.credentials == []

    def test_external_script_auth_type(self, tmp_path):
        """external_script auth type parses correctly."""
        path = tmp_path / "config.yaml"
        path.write_text("""credentials:
  - id: "github-app"
    domain: "api.github.com"
    auth:
      type: external_script
      script: "./scripts/github-app-token.sh"
      env:
        GITHUB_APP_ID: "12345"
        GITHUB_PRIVATE_KEY_PATH: "/path/to/key.pem"
      refresh_interval: 600
""")
        config = load_config(str(path))
        assert len(config.credentials) == 1
        rule = config.credentials[0]
        assert rule.auth.type == "external_script"
        assert rule.auth.script == "./scripts/github-app-token.sh"
        assert rule.auth.env == {
            "GITHUB_APP_ID": "12345",
            "GITHUB_PRIVATE_KEY_PATH": "/path/to/key.pem",
        }
        assert rule.auth.refresh_interval == 600

    def test_external_script_defaults(self, tmp_path):
        """external_script defaults: empty env, 3600 refresh."""
        path = tmp_path / "config.yaml"
        path.write_text("""credentials:
  - id: "simple"
    domain: "api.example.com"
    auth:
      type: external_script
      script: "./token.sh"
""")
        config = load_config(str(path))
        rule = config.credentials[0]
        assert rule.auth.env == {}
        assert rule.auth.refresh_interval == 3600
