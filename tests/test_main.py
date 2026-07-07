"""
Regression test: main.py must be import-safe. Its entire pipeline
(enforcer/crawler setup, all scanner runs, DB writes, HTML/PDF report
generation) is meant to live inside `if __name__ == "__main__":`, so
merely importing the module - as any test runner, linter, or another
module doing `import main` would - must not run a scan, touch the
network, or write any files.
"""
import sys


def test_import_main_has_no_side_effects(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sys.modules.pop("main", None)

    import main  # noqa: F401

    assert list(tmp_path.iterdir()) == []
    assert not hasattr(main, "scan_id")
    assert not hasattr(main, "results")
