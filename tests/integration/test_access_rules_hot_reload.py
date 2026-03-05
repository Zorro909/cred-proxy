"""AC-10.61 to AC-10.66: Hot reload integration tests for access rules."""

from auth_injection_proxy.access.store import AccessRuleStore


class TestAccessRulesHotReload:
    def test_main_file_hot_reload(self, tmp_path):
        """AC-10.61: Modifying access-rules.yaml triggers reload and takes effect."""
        main = tmp_path / "access-rules.yaml"
        main.write_text("""access_rules:
  - id: r1
    domain: a.com
    mode: allow
    paths: ["^/api/"]
""")
        store = AccessRuleStore(tmp_path)
        assert len(store.rules) == 1

        main.write_text("""access_rules:
  - id: r1
    domain: a.com
    mode: deny
    paths: ["^/admin"]
""")
        store.reload()
        assert len(store.rules) == 1
        assert store.rules[0].mode == "deny"

    def test_drop_in_file_added(self, tmp_path):
        """AC-10.62: Adding a new .yaml file to access-rules.d/ triggers reload."""
        d = tmp_path / "access-rules.d"
        d.mkdir()
        store = AccessRuleStore(tmp_path)
        assert len(store.rules) == 0

        (d / "github.yaml").write_text("""access_rules:
  - id: r1
    domain: api.github.com
    mode: allow
    paths: ["^/repos/"]
""")
        store.reload()
        assert len(store.rules) == 1

    def test_drop_in_file_removed(self, tmp_path):
        """AC-10.63: Removing a file from access-rules.d/ triggers reload and removes rules."""
        d = tmp_path / "access-rules.d"
        d.mkdir()
        (d / "github.yaml").write_text("""access_rules:
  - id: r1
    domain: api.github.com
    mode: allow
    paths: ["^/repos/"]
""")
        store = AccessRuleStore(tmp_path)
        assert len(store.rules) == 1

        (d / "github.yaml").unlink()
        store.reload()
        assert len(store.rules) == 0

    def test_drop_in_file_modified(self, tmp_path):
        """AC-10.64: Modifying a drop-in file triggers reload with updated rules."""
        d = tmp_path / "access-rules.d"
        d.mkdir()
        (d / "github.yaml").write_text("""access_rules:
  - id: r1
    domain: api.github.com
    mode: allow
    paths: ["^/repos/"]
""")
        store = AccessRuleStore(tmp_path)
        assert store.rules[0].paths == ["^/repos/"]

        (d / "github.yaml").write_text("""access_rules:
  - id: r1
    domain: api.github.com
    mode: allow
    paths: ["^/repos/", "^/user$"]
""")
        store.reload()
        assert store.rules[0].paths == ["^/repos/", "^/user$"]

    def test_invalid_reload_keeps_previous(self, tmp_path):
        """AC-10.65: Invalid YAML on reload keeps previous rules active."""
        main = tmp_path / "access-rules.yaml"
        main.write_text("""access_rules:
  - id: r1
    domain: a.com
    mode: allow
    paths: ["^/api/"]
""")
        store = AccessRuleStore(tmp_path)
        assert len(store.rules) == 1

        # Write invalid YAML — reload aborts and keeps previous rules
        main.write_text("{{{invalid yaml")
        result = store.reload()
        assert len(result) == 1
        assert result[0].id == "r1"
        assert result[0].domain == "a.com"

    def test_duplicate_id_after_reload_keeps_previous(self, tmp_path):
        """AC-10.66: Reload that would cause duplicate IDs keeps previous rules."""
        d = tmp_path / "access-rules.d"
        d.mkdir()
        (d / "a.yaml").write_text("""access_rules:
  - id: r1
    domain: a.com
    mode: allow
    paths: []
""")
        store = AccessRuleStore(tmp_path)
        assert len(store.rules) == 1

        # Add another file that creates a duplicate ID
        (d / "b.yaml").write_text("""access_rules:
  - id: r1
    domain: b.com
    mode: deny
    paths: []
""")
        # reload() now catches ValueError and preserves previous state
        result = store.reload()
        assert len(result) == 1
        assert result[0].id == "r1"
        assert result[0].domain == "a.com"
        # Verify store state is also preserved
        assert len(store.rules) == 1
        assert store.rules[0].domain == "a.com"
