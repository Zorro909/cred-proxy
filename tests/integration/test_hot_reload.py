"""AC-5.3–5.5: Hot-reload integration tests."""

from auth_injection_proxy.store.yaml_store import YamlCredentialStore


class TestHotReload:
    def test_reload_adds_new_rule(self, tmp_path):
        """AC-5.3: New rule appears after reload."""
        path = tmp_path / "creds.yaml"
        path.write_text(
            "credentials:\n  - id: r1\n    domain: a.com\n    auth:\n"
            "      type: bearer\n      token: t1\n"
        )
        store = YamlCredentialStore(str(path))
        assert len(store._rules) == 1

        # Add a second rule
        path.write_text(
            "credentials:\n"
            "  - id: r1\n    domain: a.com\n    auth:\n"
            "      type: bearer\n      token: t1\n"
            "  - id: r2\n    domain: b.com\n    auth:\n"
            "      type: bearer\n      token: t2\n"
        )
        store.reload()
        assert len(store._rules) == 2

    def test_reload_removes_deleted_rule(self, tmp_path):
        """AC-5.4: Deleted rule gone after reload."""
        path = tmp_path / "creds.yaml"
        path.write_text(
            "credentials:\n"
            "  - id: r1\n    domain: a.com\n    auth:\n"
            "      type: bearer\n      token: t1\n"
            "  - id: r2\n    domain: b.com\n    auth:\n"
            "      type: bearer\n      token: t2\n"
        )
        store = YamlCredentialStore(str(path))
        assert len(store._rules) == 2

        # Remove second rule
        path.write_text(
            "credentials:\n  - id: r1\n    domain: a.com\n    auth:\n"
            "      type: bearer\n      token: t1\n"
        )
        store.reload()
        assert len(store._rules) == 1
        assert store._rules[0].id == "r1"

    def test_reload_invalid_keeps_previous(self, tmp_path):
        """AC-5.5: Invalid YAML keeps previous rules."""
        path = tmp_path / "creds.yaml"
        path.write_text(
            "credentials:\n  - id: r1\n    domain: a.com\n    auth:\n"
            "      type: bearer\n      token: t1\n"
        )
        store = YamlCredentialStore(str(path))
        assert len(store._rules) == 1

        path.write_text("{{{invalid yaml")
        store.reload()
        assert len(store._rules) == 1
