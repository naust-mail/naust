"""Tests for _ANSI_RE in setup/boxctl/doctor.py.

The regex was broadened to cover CSI, OSC, and other escape sequences beyond
simple colour codes. These tests guard against regressions that would leave
raw escape bytes in the TUI log viewer output.
"""

from boxctl.doctor import _ANSI_RE  # noqa: PLC2701


def _strip(s: str) -> str:
	return _ANSI_RE.sub("", s)


# ---------------------------------------------------------------------------
# SGR / CSI colour and attribute codes
# ---------------------------------------------------------------------------


class TestSgrCsi:
	def test_plain_colour_reset(self):
		assert not _strip("\x1b[0m")

	def test_bold(self):
		assert not _strip("\x1b[1m")

	def test_fg_colour(self):
		assert not _strip("\x1b[31m")

	def test_256_colour(self):
		assert not _strip("\x1b[38;5;200m")

	def test_rgb_truecolour(self):
		assert not _strip("\x1b[38;2;255;128;0m")

	def test_text_preserved_around_colour(self):
		assert _strip("\x1b[32mhello\x1b[0m") == "hello"

	def test_multiple_codes_stripped(self):
		assert _strip("\x1b[1m\x1b[31mERROR\x1b[0m") == "ERROR"

	def test_question_mark_private_csi(self):
		# ?25l / ?25h (cursor hide/show) are CSI sequences with ? prefix
		assert not _strip("\x1b[?25l")
		assert not _strip("\x1b[?25h")


# ---------------------------------------------------------------------------
# Cursor movement / erase CSI sequences
# ---------------------------------------------------------------------------


class TestCursorCsi:
	def test_cursor_up(self):
		assert not _strip("\x1b[2A")

	def test_cursor_column(self):
		assert not _strip("\x1b[40G")

	def test_erase_line(self):
		assert not _strip("\x1b[2K")

	def test_erase_display(self):
		assert not _strip("\x1b[2J")


# ---------------------------------------------------------------------------
# OSC sequences (window title, hyperlinks)
# ---------------------------------------------------------------------------


class TestOsc:
	def test_osc_window_title_bel_terminated(self):
		assert not _strip("\x1b]0;My Title\x07")

	def test_osc_window_title_st_terminated(self):
		assert not _strip("\x1b]0;My Title\x1b\\")

	def test_osc_hyperlink(self):
		assert _strip("\x1b]8;;https://example.com\x07link\x1b]8;;\x07") == "link"


# ---------------------------------------------------------------------------
# Mixed real output
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# VT100 private single-character sequences (ESC + digit)
# ---------------------------------------------------------------------------


class TestVt100SingleChar:
	def test_save_cursor(self):
		# ESC 7 (DECSC) - would render as raw '7' without stripping
		assert not _strip("\x1b7")

	def test_restore_cursor(self):
		# ESC 8 (DECRC) - same
		assert not _strip("\x1b8")

	def test_text_around_save_restore_preserved(self):
		assert _strip("before\x1b7inside\x1b8after") == "beforeinsideafter"

	def test_application_keypad_mode(self):
		# ESC = (DECKPAM, 0x3D) - emitted by readline/ncurses, outside [0-9] range
		assert not _strip("\x1b=")

	def test_numeric_keypad_mode(self):
		# ESC > (DECKPNM, 0x3E)
		assert not _strip("\x1b>")

	# ---------------------------------------------------------------------------
	def test_coloured_log_line(self):
		line = "\x1b[1;32m[OK]\x1b[0m Service started"
		assert _strip(line) == "[OK] Service started"

	def test_progress_bar_with_cursor_movement(self):
		line = "\x1b[2K\x1b[1GLoading... 50%"
		assert _strip(line) == "Loading... 50%"

	def test_plain_text_unchanged(self):
		line = "No escape sequences here"
		assert _strip(line) == line

	def test_empty_string_unchanged(self):
		assert not _strip("")


# ---------------------------------------------------------------------------
# Truncated / malformed sequences
# ---------------------------------------------------------------------------


class TestTruncatedSequences:
	def test_truncated_csi_passes_through(self):
		# CSI with no final letter - should not be consumed, not silently dropped
		assert _strip("\x1b[31") == "\x1b[31"

	def test_truncated_osc_stripped_to_end(self):
		# OSC with no BEL/ST terminator: strip greedily to end of string.
		# Leaving it raw would corrupt terminal state in the TUI log viewer.
		assert not _strip("\x1b]0;unterminated")


# ---------------------------------------------------------------------------
# Complex OSC sequences
# ---------------------------------------------------------------------------


class TestOscComplex:
	def test_osc_with_url_and_semicolons(self):
		# Hyperlink OSC with semicolons and query string - must not stop early
		s = "\x1b]8;id=foo;https://example.com/path?a=1&b=2\x07text\x1b]8;;\x07"
		assert _strip(s) == "text"

	def test_multiple_osc_in_one_line(self):
		# tmux emits title-set OSC before every prompt; all must be stripped
		s = "\x1b]0;title\x07\x1b[32mOK\x1b[0m \x1b]0;other\x07done"
		assert _strip(s) == "OK done"


# ---------------------------------------------------------------------------
# Non-escape control bytes must not be affected
# ---------------------------------------------------------------------------


class TestNullByte:
	def test_null_byte_not_stripped(self):
		# Regex must not consume non-escape control bytes
		assert _strip("\x1b[0m\x00hello") == "\x00hello"
