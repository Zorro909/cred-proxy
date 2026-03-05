"""AC-10.23 to AC-10.34: Unit tests for AccessRuleStore."""

import pytest

from auth_injection_proxy.access.models import AccessRule
from auth_injection_proxy.access.store import AccessRuleStore


def _write_main(tmp_path, content):
    (tmp_path / "access-rules.yaml").write_text(content)


def _write_drop_in(tmp_path, filename, content):
    d = tmp_path / "access-rules.d"
    d.mkdir(exist_ok=True)
    (d / filename).write_text(content)


class TestAccessRuleStore:
    def test_load_main_file(self, tmp_path):
        """AC-10.23: Store loads rules from access-rules.yaml."""
        _write_main(tmp_path, """access_rules:
  - id: r1
    domain: api.github.com
    mode: allow
    paths:
      - "^/repos/"
""")
        store = AccessRuleStore(tmp_path)
        assert len(store.rules) == 1
        assert store.rules[0].id == "r1"

    def test_load_drop_in_files(self, tmp_path):
        """AC-10.24: Store loads rules from access-rules.d/*.yaml in sorted order."""
        _write_drop_in(tmp_path, "b_github.yaml", """access_rules:
  - id: r2
    domain: api.github.com
    mode: allow
    paths: ["^/repos/"]
""")
        _write_drop_in(tmp_path, "a_openai.yaml", """access_rules:
  - id: r1
    domain: api.openai.com
    mode: deny
    paths: ["^/v1/files"]
""")
        store = AccessRuleStore(tmp_path)
        assert len(store.rules) == 2
        # a_openai loaded first (sorted), so r1 comes first
        assert store.rules[0].id == "r1"
        assert store.rules[1].id == "r2"

    def test_merge_main_and_drop_in(self, tmp_path):
        """AC-10.25: Rules from main file and drop-in files are merged."""
        _write_main(tmp_path, """access_rules:
  - id: r1
    domain: api.github.com
    mode: allow
    paths: ["^/repos/"]
""")
        _write_drop_in(tmp_path, "openai.yaml", """access_rules:
  - id: r2
    domain: api.openai.com
    mode: deny
    paths: ["^/v1/files"]
""")
        store = AccessRuleStore(tmp_path)
        assert len(store.rules) == 2
        groups = store.groups
        assert "default" in groups
        assert "openai" in groups

    def test_no_files_empty_rules(self, tmp_path):
        """AC-10.26: Store returns empty list when neither file nor directory exists."""
        store = AccessRuleStore(tmp_path)
        assert store.rules == []

    def test_duplicate_ids_across_files(self, tmp_path):
        """AC-10.27: Duplicate IDs across main + drop-in raises ValueError."""
        _write_main(tmp_path, """access_rules:
  - id: r1
    domain: api.github.com
    mode: allow
    paths: []
""")
        _write_drop_in(tmp_path, "dup.yaml", """access_rules:
  - id: r1
    domain: api.openai.com
    mode: deny
    paths: []
""")
        with pytest.raises(ValueError, match="Duplicate access rule IDs"):
            AccessRuleStore(tmp_path)

    def test_duplicate_domains_across_files(self, tmp_path):
        """AC-10.28: Duplicate domains across files raises ValueError."""
        _write_main(tmp_path, """access_rules:
  - id: r1
    domain: api.github.com
    mode: allow
    paths: []
""")
        _write_drop_in(tmp_path, "dup.yaml", """access_rules:
  - id: r2
    domain: api.github.com
    mode: deny
    paths: []
""")
        with pytest.raises(ValueError, match="Duplicate access rule domains"):
            AccessRuleStore(tmp_path)

    def test_invalid_drop_in_skipped(self, tmp_path):
        """AC-10.29: Invalid YAML in one drop-in file skips it, loads others."""
        _write_drop_in(tmp_path, "good.yaml", """access_rules:
  - id: r1
    domain: api.github.com
    mode: allow
    paths: ["^/repos/"]
""")
        _write_drop_in(tmp_path, "bad.yaml", "{{{invalid yaml")
        store = AccessRuleStore(tmp_path)
        assert len(store.rules) == 1
        assert store.rules[0].id == "r1"

    async def test_crud_operations(self, tmp_path):
        """AC-10.30: Create/read/update/delete access rules through store."""
        store = AccessRuleStore(tmp_path)

        # Create
        rule = AccessRule(id="r1", domain="api.github.com", mode="allow", paths=["^/repos/"])
        await store.create(rule)
        assert len(store.rules) == 1

        # Read
        result = await store.get("r1")
        assert result is not None
        group_name, found = result
        assert found.id == "r1"
        assert group_name == "default"

        # Update
        updated = AccessRule(id="r1", domain="api.github.com", mode="deny", paths=["^/admin"])
        await store.update("r1", updated)
        result = await store.get("r1")
        assert result is not None
        _, found = result
        assert found.mode == "deny"

        # Delete
        await store.delete("r1")
        assert len(store.rules) == 0

    async def test_save_writes_to_main_file(self, tmp_path):
        """AC-10.31: CRUD operations write to access-rules.yaml for default group."""
        store = AccessRuleStore(tmp_path)
        rule = AccessRule(id="r1", domain="api.github.com", mode="allow", paths=["^/repos/"])
        await store.create(rule)
        assert (tmp_path / "access-rules.yaml").exists()

        # Verify file content
        store2 = AccessRuleStore(tmp_path)
        assert len(store2.rules) == 1
        assert store2.rules[0].id == "r1"

    def test_sorted_file_loading(self, tmp_path):
        """AC-10.32: Drop-in files loaded in lexicographic order."""
        _write_drop_in(tmp_path, "z_last.yaml", """access_rules:
  - id: r3
    domain: c.com
    mode: deny
    paths: []
""")
        _write_drop_in(tmp_path, "a_first.yaml", """access_rules:
  - id: r1
    domain: a.com
    mode: allow
    paths: []
""")
        _write_drop_in(tmp_path, "m_middle.yaml", """access_rules:
  - id: r2
    domain: b.com
    mode: deny
    paths: []
""")
        store = AccessRuleStore(tmp_path)
        assert [r.id for r in store.rules] == ["r1", "r2", "r3"]

    def test_invalid_mode_rejected(self, tmp_path):
        """AC-10.33: Mode other than 'allow'/'deny' raises ValidationError.
        The store's _load_file catches ValidationError and skips the file,
        so the store loads with 0 rules (file is skipped)."""
        _write_main(tmp_path, """access_rules:
  - id: r1
    domain: api.github.com
    mode: block
    paths: []
""")
        store = AccessRuleStore(tmp_path)
        # Invalid file is skipped, no rules loaded
        assert len(store.rules) == 0

    def test_invalid_regex_rejected_on_load(self, tmp_path):
        """AC-10.34: Invalid regex in YAML raises ValidationError.
        The store's _load_file catches ValidationError and skips the file."""
        _write_main(tmp_path, """access_rules:
  - id: r1
    domain: api.github.com
    mode: allow
    paths:
      - "[invalid"
""")
        store = AccessRuleStore(tmp_path)
        # Invalid file is skipped, no rules loaded
        assert len(store.rules) == 0
