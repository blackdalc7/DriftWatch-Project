from datetime import datetime, timezone
from pathlib import Path

import jsonschema
import pytest
import yaml

from driftwatch.catalog import (
    CATALOG,
    CatalogError,
    ParamSpec,
    actions_for_technique,
    catalog_as_dicts,
    get_action,
    marker_for,
    techniques_for_step,
    validate_step,
)
from driftwatch.library import Library, LibraryError, approve, dump_test, load_file, verify
from driftwatch.schema import DriftwatchTest, Expected, Outcome, ReviewStatus, export_json_schema

ROOT = Path(__file__).resolve().parents[1]


def minimal(**over):
    data = {
        "id": "dw-test-example",
        "name": "Example test",
        "description": "An example test used in unit tests.",
        "platforms": ["windows"],
        "attack": {"tactic": "discovery", "techniques": ["T1033"]},
        "steps": [{"action": "process.discovery", "params": {"command": "whoami_all"}}],
    }
    data.update(over)
    return data


def test_catalog_has_no_free_form_parameters():
    for action in CATALOG.values():
        for p in action.params:
            assert p.kind in ("enum", "int", "bool")


def test_validate_step_fills_defaults_and_rejects_unknown():
    assert validate_step("file.eicar_drop", {}) == {"wait_seconds": 10}
    with pytest.raises(CatalogError, match="does not accept"):
        validate_step("file.eicar_drop", {"path": "C:/x"})
    with pytest.raises(CatalogError, match="unknown action"):
        validate_step("shell.exec", {"cmd": "whoami"})
    with pytest.raises(CatalogError, match="requires parameter"):
        validate_step("process.discovery", {})
    with pytest.raises(CatalogError, match="one of"):
        validate_step("process.discovery", {"command": "rm -rf /"})


def test_validate_step_platform_rules():
    with pytest.raises(CatalogError, match="does not support platform"):
        validate_step("registry.run_key_canary", {}, "linux")
    with pytest.raises(CatalogError, match="linux choice"):
        validate_step("process.discovery", {"command": "id"}, "windows")
    assert validate_step("process.discovery", {"command": "id"}, "linux") == {"command": "id"}


def test_param_spec_validation():
    spec = ParamSpec("n", "int", "n", minimum=1, maximum=3)
    for bad in (0, 4, True, "2"):
        with pytest.raises(CatalogError):
            spec.validate(bad)
    assert ParamSpec("b", "bool", "b").validate(True) is True
    with pytest.raises(CatalogError):
        ParamSpec("b", "bool", "b").validate("yes")


def test_technique_lookup_both_ways():
    assert techniques_for_step("process.discovery", {"command": "net_localgroup_admins"}) == ("T1069.001",)
    assert techniques_for_step("powershell.encoded_marker", {}) == ("T1059.001", "T1027")
    ids = [(a.id, p) for a, p in actions_for_technique("T1033")]
    assert ("process.discovery", {"command": "whoami_all"}) in ids
    assert actions_for_technique("T1190") == []
    assert all(a.id != "hygiene.collect" for a, _ in actions_for_technique("T1082"))


def test_marker_requires_run_id_format():
    assert marker_for("0123456789abcdef") == "DW-0123456789abcdef"
    with pytest.raises(CatalogError):
        marker_for("not-a-run")
    assert get_action("dns.sinkhole_query").techniques == ("T1071.004",)
    assert {a["id"] for a in catalog_as_dicts()} == set(CATALOG)


def test_schema_rejects_bad_tests():
    DriftwatchTest.model_validate(minimal())
    with pytest.raises(ValueError, match="not in the Safe Action Catalog"):
        DriftwatchTest.model_validate(minimal(steps=[{"action": "shell.exec"}]))
    with pytest.raises(ValueError):
        DriftwatchTest.model_validate(minimal(attack={"tactic": "hacking", "techniques": ["T1033"]}))
    with pytest.raises(ValueError):
        DriftwatchTest.model_validate(minimal(attack={"tactic": "discovery", "techniques": ["1033"]}))
    with pytest.raises(ValueError):
        DriftwatchTest.model_validate(minimal(platforms=["macos"]))
    with pytest.raises(ValueError, match="approved_by"):
        DriftwatchTest.model_validate(minimal(status="approved"))
    with pytest.raises(ValueError, match="verified test"):
        DriftwatchTest.model_validate(minimal(status="verified", review={"approved_by": "a"}))
    with pytest.raises(ValueError):
        DriftwatchTest.model_validate(minimal(extra_field=1))
    with pytest.raises(ValueError):
        Expected(outcome=Outcome.MISSED)


def test_expected_passes():
    assert Expected(outcome=Outcome.DETECTED).passes(Outcome.PREVENTED)
    assert not Expected(outcome=Outcome.PREVENTED).passes(Outcome.DETECTED)
    assert not Expected().passes(Outcome.MISSED)


def test_json_schema_validates_every_library_file():
    schema = export_json_schema()
    for path in (ROOT / "library/tests").glob("*.yml"):
        jsonschema.validate(yaml.safe_load(path.read_text()), schema)
    committed = ROOT / "schema/driftwatch-test.schema.json"
    assert committed.exists()


def test_library_loads_and_detects_duplicates(tmp_path):
    lib = Library(ROOT / "library/tests")
    assert len(lib) == 10 and "dw-win-whoami-discovery" in lib
    assert lib.get("dw-lin-host-discovery").emulated_techniques() == ["T1033", "T1082"]
    (tmp_path / "a.yml").write_text(yaml.safe_dump(minimal()))
    (tmp_path / "b.yml").write_text(yaml.safe_dump(minimal()))
    with pytest.raises(LibraryError, match="duplicate"):
        Library(tmp_path)
    with pytest.raises(LibraryError, match="unknown"):
        lib.get("dw-nope")


def test_load_file_errors(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("- just\n- a list\n")
    with pytest.raises(LibraryError, match="mapping"):
        load_file(bad)
    bad.write_text("id: [unclosed")
    with pytest.raises(LibraryError, match="YAML"):
        load_file(bad)
    bad.write_text(yaml.safe_dump(minimal(id="BAD")))
    with pytest.raises(LibraryError):
        load_file(bad)


def test_review_and_verification_gates(tmp_path):
    draft = DriftwatchTest.model_validate(minimal())
    with pytest.raises(LibraryError, match="reviewer"):
        approve(draft, "  ")
    with pytest.raises(LibraryError, match="only approved"):
        verify(draft, "0" * 16, "agt", True)
    approved = approve(draft, "alvin", "looks benign", now=datetime(2026, 10, 30, tzinfo=timezone.utc))
    assert approved.status is ReviewStatus.APPROVED and approved.review.approved_by == "alvin"
    with pytest.raises(LibraryError, match="only drafts"):
        approve(approved, "alvin")
    with pytest.raises(LibraryError, match="did not execute"):
        verify(approved, "0" * 16, "agt", False)
    verified = verify(approved, "0123456789abcdef", "agt_1", True)
    assert verified.status is ReviewStatus.VERIFIED and verified.dispatchable
    lib = Library(tmp_path)
    path = lib.save(verified, tmp_path / "t.yml")
    assert "status: verified" in path.read_text()
    assert Library(tmp_path).get("dw-test-example").verification.run_id == "0123456789abcdef"
    with pytest.raises(LibraryError, match="no file known"):
        Library(tmp_path / "empty").save(DriftwatchTest.model_validate(minimal(id="dw-other")))
    assert "steps:" in dump_test(verified)
