"""cisco-ai-skill-scanner location remap: synthesized ``SKILL.md`` findings
(lenient mode, no real manifest) are repointed at the real markdown file."""

from __future__ import annotations

from deepscan_core.scanners.cisco_ai_skill_scanner import _remap_synthetic_location


def test_synthetic_skill_md_remaps_to_readme(tmp_path):
    (tmp_path / "README.md").write_text("# project\n", encoding="utf-8")
    # No SKILL.md exists → the 'SKILL.md' location is synthetic; point it at the
    # markdown the lenient fallback actually read (sorted-first *.md), with a line.
    assert _remap_synthetic_location(tmp_path, "SKILL.md") == "README.md:1"


def test_real_existing_location_is_unchanged(tmp_path):
    (tmp_path / "SKILL.md").write_text("---\nname: x\n---\n", encoding="utf-8")
    assert _remap_synthetic_location(tmp_path, "SKILL.md") == "SKILL.md"
    # A real content finding with a line is left intact.
    (tmp_path / "tool.py").write_text("x = 1\n", encoding="utf-8")
    assert _remap_synthetic_location(tmp_path, "tool.py:42") == "tool.py:42"


def test_synthetic_in_subdir_uses_that_dirs_markdown(tmp_path):
    sub = tmp_path / "skills" / "alpha"
    sub.mkdir(parents=True)
    (sub / "GUIDE.md").write_text("# alpha\n", encoding="utf-8")
    assert (
        _remap_synthetic_location(tmp_path, "skills/alpha/SKILL.md")
        == "skills/alpha/GUIDE.md:1"
    )


def test_sorted_first_markdown_is_chosen(tmp_path):
    (tmp_path / "README.md").write_text("# r\n", encoding="utf-8")
    (tmp_path / "AAA.md").write_text("# a\n", encoding="utf-8")
    # sorted(glob('*.md'))[0] == 'AAA.md' - matches the tool's own selection.
    assert _remap_synthetic_location(tmp_path, "SKILL.md") == "AAA.md:1"


def test_no_markdown_leaves_location_unchanged(tmp_path):
    assert _remap_synthetic_location(tmp_path, "SKILL.md") == "SKILL.md"
