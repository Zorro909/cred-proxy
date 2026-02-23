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
