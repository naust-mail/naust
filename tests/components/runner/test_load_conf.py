"""
Tests for components.runner.load_conf().

Covers key-value parsing, quote stripping, and the missing-file behavior
(returns {} instead of raising, matching boxctl.runner.load_conf behavior).
"""

from components.runner import load_conf


def test_simple_key_value(tmp_path):
	p = tmp_path / "conf"
	p.write_text("KEY=VALUE\n")
	assert load_conf(str(p)) == {"KEY": "VALUE"}


def test_single_quoted_value(tmp_path):
	p = tmp_path / "conf"
	p.write_text("KEY='quoted value'\n")
	assert load_conf(str(p)) == {"KEY": "quoted value"}


def test_double_quoted_value(tmp_path):
	p = tmp_path / "conf"
	p.write_text('KEY="quoted value"\n')
	assert load_conf(str(p)) == {"KEY": "quoted value"}


def test_comment_skipped(tmp_path):
	p = tmp_path / "conf"
	p.write_text("# comment\nKEY=VALUE\n")
	assert load_conf(str(p)) == {"KEY": "VALUE"}


def test_blank_lines_skipped(tmp_path):
	p = tmp_path / "conf"
	p.write_text("\n\nKEY=VALUE\n\n")
	assert load_conf(str(p)) == {"KEY": "VALUE"}


def test_line_without_equals_skipped(tmp_path):
	p = tmp_path / "conf"
	p.write_text("NOTAKEYVALUE\nKEY=VALUE\n")
	assert load_conf(str(p)) == {"KEY": "VALUE"}


def test_value_with_equals_sign(tmp_path):
	"""Only the first '=' is used as delimiter; trailing '=' stays in value."""
	p = tmp_path / "conf"
	p.write_text("KEY=a=b\n")
	assert load_conf(str(p)) == {"KEY": "a=b"}


def test_multiple_keys(tmp_path):
	p = tmp_path / "conf"
	p.write_text("A=1\nB=2\nC=3\n")
	assert load_conf(str(p)) == {"A": "1", "B": "2", "C": "3"}


def test_empty_file(tmp_path):
	p = tmp_path / "conf"
	p.write_text("")
	assert load_conf(str(p)) == {}


def test_missing_file_returns_empty_dict():
	"""Missing file must return {} not raise FileNotFoundError."""
	result = load_conf("/nonexistent/path/to/naust.conf")
	assert result == {}


def test_key_whitespace_stripped(tmp_path):
	p = tmp_path / "conf"
	p.write_text("KEY =VALUE\n")
	assert load_conf(str(p)) == {"KEY": "VALUE"}


def test_value_whitespace_stripped(tmp_path):
	p = tmp_path / "conf"
	p.write_text("KEY= VALUE\n")
	assert load_conf(str(p)) == {"KEY": "VALUE"}
