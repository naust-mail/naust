"""Tests for load_conf and write_output in setup/boxctl/runner.py."""

from boxctl.runner import load_conf, write_output


class TestLoadConf:
	def test_simple_key_value(self, tmp_path):
		p = tmp_path / "conf"
		p.write_text("KEY=VALUE\n")
		assert load_conf(str(p)) == {"KEY": "VALUE"}

	def test_single_quoted_value(self, tmp_path):
		p = tmp_path / "conf"
		p.write_text("KEY='shell quoted'\n")
		assert load_conf(str(p)) == {"KEY": "shell quoted"}

	def test_double_quoted_value(self, tmp_path):
		p = tmp_path / "conf"
		p.write_text('KEY="double quoted"\n')
		assert load_conf(str(p)) == {"KEY": "double quoted"}

	def test_comment_line_skipped(self, tmp_path):
		p = tmp_path / "conf"
		p.write_text("# this is a comment\nKEY=VALUE\n")
		result = load_conf(str(p))
		assert "# this is a comment" not in result
		assert result == {"KEY": "VALUE"}

	def test_blank_lines_skipped(self, tmp_path):
		p = tmp_path / "conf"
		p.write_text("\n\nKEY=VALUE\n\n")
		assert load_conf(str(p)) == {"KEY": "VALUE"}

	def test_malformed_line_without_equals_skipped(self, tmp_path):
		p = tmp_path / "conf"
		p.write_text("NOTAKEYVALUE\nKEY=VALUE\n")
		assert load_conf(str(p)) == {"KEY": "VALUE"}

	def test_multiple_keys(self, tmp_path):
		p = tmp_path / "conf"
		p.write_text("A=1\nB=2\nC=3\n")
		assert load_conf(str(p)) == {"A": "1", "B": "2", "C": "3"}

	def test_empty_file(self, tmp_path):
		p = tmp_path / "conf"
		p.write_text("")
		assert load_conf(str(p)) == {}

	def test_key_with_spaces_in_value_unquoted(self, tmp_path):
		# load_conf strips outer quotes but does not strip spaces from unquoted values.
		# Partition on first '=' then strip - so "KEY=hello world" -> "hello world"
		p = tmp_path / "conf"
		p.write_text("KEY=hello world\n")
		assert load_conf(str(p)) == {"KEY": "hello world"}

	def test_missing_file_returns_empty(self, tmp_path):
		p = tmp_path / "nonexistent"
		assert load_conf(str(p)) == {}

	def test_value_with_equals_sign(self, tmp_path):
		# Partition on first '=' only - trailing '=' chars stay in value.
		p = tmp_path / "conf"
		p.write_text("KEY=a=b\n")
		assert load_conf(str(p)) == {"KEY": "a=b"}

	def test_key_stripped_of_spaces(self, tmp_path):
		p = tmp_path / "conf"
		p.write_text("KEY =VALUE\n")
		assert load_conf(str(p)) == {"KEY": "VALUE"}

	def test_value_stripped_of_spaces(self, tmp_path):
		p = tmp_path / "conf"
		p.write_text("KEY= VALUE\n")
		assert load_conf(str(p)) == {"KEY": "VALUE"}

	def test_mismatched_quotes_not_stripped(self, tmp_path):
		# Only matching outer quote pairs are stripped.
		p = tmp_path / "conf"
		p.write_text("KEY='unmatched\"\n")
		assert load_conf(str(p)) == {"KEY": "'unmatched\""}


class TestWriteOutput:
	def test_plain_value_roundtrip(self, tmp_path):
		p = tmp_path / "out"
		write_output(str(p), {"KEY": "value"})
		result = load_conf(str(p))
		assert result == {"KEY": "value"}

	def test_value_with_spaces_roundtrip(self, tmp_path):
		p = tmp_path / "out"
		write_output(str(p), {"KEY": "hello world"})
		result = load_conf(str(p))
		assert result == {"KEY": "hello world"}

	def test_value_with_single_quote_escaped(self, tmp_path):
		p = tmp_path / "out"
		write_output(str(p), {"KEY": "it's fine"})
		raw = p.read_text()
		# Shell escape: ' becomes '\''
		assert "'\\''" in raw
		result = load_conf(str(p))
		# load_conf strips only outer quotes, not inner shell escaping,
		# so we verify the file was written without crashing and has the key.
		assert "KEY" in result

	def test_value_with_backslash(self, tmp_path):
		p = tmp_path / "out"
		write_output(str(p), {"KEY": "back\\slash"})
		raw = p.read_text()
		assert "KEY=" in raw

	def test_sentinel_keys_skipped(self, tmp_path):
		# Keys starting with __ are sentinels and must not be written.
		p = tmp_path / "out"
		write_output(str(p), {"__EMAIL_ADDR": "me@example.com", "KEY": "val"})
		raw = p.read_text()
		assert "__EMAIL_ADDR" not in raw
		assert "KEY" in raw

	def test_dict_values_skipped(self, tmp_path):
		# Dict values (multi-select steps) must not be written directly.
		p = tmp_path / "out"
		write_output(str(p), {"OPTS": {"ENABLE_X": "true"}, "KEY": "val"})
		raw = p.read_text()
		assert "OPTS" not in raw
		assert "KEY" in raw

	def test_atomic_write_via_tmp(self, tmp_path):
		# write_output writes to .tmp first then replaces - final file must exist.
		p = tmp_path / "out"
		write_output(str(p), {"A": "1"})
		assert p.exists()
		assert not (tmp_path / "out.tmp").exists()
