"""Tests for setup/tools/editconf.py invoked via subprocess."""

import os
import subprocess  # noqa: S404
import sys

EDITCONF = os.path.join(os.path.dirname(__file__), "..", "..", "setup", "tools", "editconf.py")


def run_editconf(args: list[str], *, check: bool = False) -> subprocess.CompletedProcess:
	return subprocess.run(  # noqa: S603
		[sys.executable, EDITCONF, *args],
		capture_output=True,
		text=True,
		check=False,
	)


class TestBasicReplacement:
	def test_replaces_existing_value(self, tmp_path):
		f = tmp_path / "conf"
		f.write_text("KEY=old\n")
		run_editconf([str(f), "KEY=new"])
		text = f.read_text()
		assert "KEY=new" in text
		# Old value must only appear in commented-out lines.
		active = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
		assert not any("KEY=old" in line for line in active)

	def test_appends_new_key(self, tmp_path):
		f = tmp_path / "conf"
		f.write_text("OTHER=x\n")
		run_editconf([str(f), "KEY=value"])
		text = f.read_text()
		assert "KEY=value" in text

	def test_missing_file_created(self, tmp_path):
		f = tmp_path / "newfile.conf"
		assert not f.exists()
		run_editconf([str(f), "KEY=value"])
		assert f.exists()
		assert "KEY=value" in f.read_text()

	def test_multiple_settings_one_call(self, tmp_path):
		f = tmp_path / "conf"
		f.write_text("")
		run_editconf([str(f), "KEY1=val1", "KEY2=val2"])
		text = f.read_text()
		assert "KEY1=val1" in text
		assert "KEY2=val2" in text

	def test_existing_value_unchanged_when_same(self, tmp_path):
		f = tmp_path / "conf"
		f.write_text("KEY=same\n")
		run_editconf([str(f), "KEY=same"])
		text = f.read_text()
		assert text.count("KEY=same") == 1

	def test_old_value_commented_out(self, tmp_path):
		f = tmp_path / "conf"
		f.write_text("KEY=old\n")
		run_editconf([str(f), "KEY=new"])
		text = f.read_text()
		assert "#KEY=old" in text or "# KEY=old" in text

	def test_indent_preserved(self, tmp_path):
		f = tmp_path / "conf"
		f.write_text("   KEY=old\n")
		run_editconf([str(f), "KEY=new"])
		text = f.read_text()
		# New line should carry the same leading indent.
		assert "   KEY=new" in text

	def test_duplicate_key_second_occurrence_removed(self, tmp_path):
		f = tmp_path / "conf"
		f.write_text("KEY=first\nKEY=second\n")
		run_editconf([str(f), "KEY=new"])
		text = f.read_text()
		assert text.count("KEY=new") == 1


class TestSpaceDelimiter:
	def test_space_delimiter_replaces(self, tmp_path):
		f = tmp_path / "conf"
		f.write_text("KEY old\n")
		run_editconf([str(f), "-s", "KEY=new"])
		text = f.read_text()
		assert "KEY new" in text

	def test_space_delimiter_appends(self, tmp_path):
		f = tmp_path / "conf"
		f.write_text("")
		run_editconf([str(f), "-s", "KEY=value"])
		assert "KEY value" in f.read_text()


class TestEraseMode:
	def test_erase_comments_out_existing(self, tmp_path):
		f = tmp_path / "conf"
		f.write_text("KEY=old\n")
		run_editconf([str(f), "-e", "KEY="])
		text = f.read_text()
		# Original line must be commented out.
		assert "#KEY=old" in text or "# KEY=old" in text
		# The key must not be re-added as an active setting.
		active_lines = [line for line in text.splitlines() if not line.strip().startswith("#")]
		assert not any("KEY=" in line for line in active_lines)

	def test_erase_nonexistent_key_no_op(self, tmp_path):
		f = tmp_path / "conf"
		f.write_text("OTHER=x\n")
		run_editconf([str(f), "-e", "KEY="])
		text = f.read_text()
		assert "KEY" not in text


class TestCustomCommentChar:
	def test_custom_comment_char_used(self, tmp_path):
		f = tmp_path / "conf"
		f.write_text("KEY=old\n")
		run_editconf([str(f), "-c", ";", "KEY=new"])
		text = f.read_text()
		assert ";KEY=old" in text or "; KEY=old" in text

	def test_hash_not_used_with_custom_comment(self, tmp_path):
		f = tmp_path / "conf"
		f.write_text("KEY=old\n")
		run_editconf([str(f), "-c", ";", "KEY=new"])
		text = f.read_text()
		# No '#' should appear as a comment prefix for the old line.
		for line in text.splitlines():
			if "old" in line:
				assert not line.lstrip().startswith("#")


class TestTestingMode:
	def test_testing_mode_prints_to_stdout(self, tmp_path):
		f = tmp_path / "conf"
		f.write_text("KEY=old\n")
		original = f.read_text()
		result = run_editconf([str(f), "-t", "KEY=new"])
		assert "KEY=new" in result.stdout
		# File must be unchanged.
		assert f.read_text() == original

	def test_testing_mode_file_unchanged(self, tmp_path):
		f = tmp_path / "conf"
		content = "A=1\nB=2\n"
		f.write_text(content)
		run_editconf([str(f), "-t", "A=99"])
		assert f.read_text() == content


class TestLineFolding:
	def test_folded_continuation_treated_as_one_setting(self, tmp_path):
		# A setting with a continuation line (starts with space/tab) must be
		# replaced as a single unit.
		f = tmp_path / "conf"
		f.write_text("KEY val\n  UE\n")
		run_editconf([str(f), "-w", "-s", "KEY=newval"])
		text = f.read_text()
		assert "KEY newval" in text


class TestInvalidArgs:
	def test_no_settings_exits_nonzero(self):
		# Passing only the filename with no settings should exit non-zero.
		result = run_editconf(["/dev/null"])
		assert result.returncode != 0

	def test_invalid_option_exits_nonzero(self, tmp_path):
		f = tmp_path / "conf"
		f.write_text("")
		result = run_editconf([str(f), "--invalid-option", "KEY=val"])
		assert result.returncode != 0
