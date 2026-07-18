"""Terminal UI primitives - ANSI rendering, raw input, select/text components."""

import os
import select
import sys
import termios

# ── ANSI helpers ──────────────────────────────────────────────────────────────


def _fg(r, g, b, s, bold=False):
	prefix = "\033[1;" if bold else "\033["
	return f"{prefix}38;2;{r};{g};{b}m{s}\033[0m"


def _bg_fg(bgr, bgg, bgb, fgr, fgg, fgb, s, bold=False):
	prefix = "\033[1;" if bold else "\033["
	return f"{prefix}38;2;{fgr};{fgg};{fgb}m\033[48;2;{bgr};{bgg};{bgb}m{s}\033[0m"


def lavender(s, bold=False):
	return _fg(0xA6, 0xAF, 0xF3, s, bold)


def white_b(s):
	return _fg(0xFF, 0xFF, 0xFF, s, bold=True)


def gray_num(s):
	return _fg(0x67, 0x69, 0x72, s)


def gray_desc(s):
	return _fg(0x98, 0x9B, 0xA1, s)


def gray_nav(s):
	return _fg(0x67, 0x69, 0x72, s)


def green(s):
	return _fg(0x5F, 0xFF, 0x87, s)


def red(s):
	return _fg(0xFF, 0x55, 0x55, s)


def bold(s):
	return f"\033[1m{s}\033[0m"


def nav_active(label):
	return _bg_fg(0xA6, 0xAF, 0xF3, 0x0D, 0x0E, 0x11, f" □ {label} ", bold=True)


def _term_width():
	try:
		return os.get_terminal_size().columns
	except OSError:
		return 80


HINT_SEL = "Enter to select  ·  ↑↓/Tab to navigate  ·  Esc to go back"
HINT_EDIT = "Enter to confirm  ·  ←→ to move cursor  ·  Esc to cancel"
HINT_TEXT = "Enter to confirm  ·  ←→ to move cursor  ·  Esc to go back"
HINT_PW = "Enter to confirm  ·  Esc to go back"
HINT_MULTI = "Space to toggle  ·  ↑↓/Tab to navigate  ·  Enter to confirm  ·  Esc to go back"
HINT_FILTER = "↓ browse matches  ·  Enter to confirm  ·  Esc to go back"
HINT_FLIST = "↑↓ navigate  ·  Enter to select  ·  type to filter"

_FILTER_MAX = 6

# ── Terminal raw mode ─────────────────────────────────────────────────────────


class Raw:
	def __enter__(self):
		self.fd = sys.stdin.fileno()
		self.old = termios.tcgetattr(self.fd)
		mode = termios.tcgetattr(self.fd)
		mode[0] &= ~(termios.BRKINT | termios.ICRNL | termios.INPCK | termios.ISTRIP | termios.IXON)
		mode[2] &= ~(termios.CSIZE | termios.PARENB)
		mode[2] |= termios.CS8
		mode[3] &= ~(termios.ECHO | termios.ICANON | termios.IEXTEN | termios.ISIG)
		mode[6][termios.VMIN] = 1
		mode[6][termios.VTIME] = 0
		termios.tcsetattr(self.fd, termios.TCSADRAIN, mode)
		return self

	def __exit__(self, *_):
		termios.tcsetattr(self.fd, termios.TCSADRAIN, self.old)


def read_key():
	"""Read one logical keypress, accumulating CSI sequences with a 50ms timeout."""
	fd = sys.stdin.fileno()

	def _rb():
		try:
			return os.read(fd, 1)
		except OSError:
			return b'\x03'

	b = _rb()

	if b != b'\x1b':
		if b in {b'\r', b'\n'}:
			return 'enter'
		if b == b'\x03':
			return 'ctrl_c'
		if b == b'\t':
			return 'tab'
		if b == b'\x7f':
			return 'backspace'
		if b == b'\x01':
			return 'home'
		if b == b'\x05':
			return 'end'
		return b.decode('utf-8', errors='replace')

	if not select.select([fd], [], [], 0.05)[0]:
		return 'esc'

	b2 = _rb()
	if b2 != b'[':
		return 'esc'

	seq = b''
	while True:
		if not select.select([fd], [], [], 0.05)[0]:
			break
		ch = _rb()
		seq += ch
		if 0x40 <= ch[0] <= 0x7E:
			break

	if seq == b'A':
		return 'up'
	if seq == b'B':
		return 'down'
	if seq == b'C':
		return 'right'
	if seq == b'D':
		return 'left'
	if seq == b'Z':
		return 'shift_tab'
	return ''


# ── Layout ────────────────────────────────────────────────────────────────────


def clear():
	print("\033[H\033[J", end="", flush=True)


def nav(labels, current, done):
	"""
	Render the step nav bar, windowed to fit the terminal width.
	The window always contains `current`. Steps that scroll off either
	edge are replaced with a dim "..." marker.

	`current` may be None (editing a preset field from the confirm screen
	that isn't one of this run's active steps - see runner.py). No label
	gets the active highlight in that case; the window anchors on the last
	label ("Confirm") since that's where control returns to afterward.
	"""
	cols = _term_width()
	sep = "  "

	# Build rendered tokens (label + state) for all steps
	rendered = []
	for i, label in enumerate(labels):
		if i in done:
			rendered.append(green(f"{label} ✓"))
		elif i == current:
			rendered.append(nav_active(label))
		else:
			rendered.append(gray_nav(f"□ {label}"))

	# Visible width of a rendered token (strip ANSI for measurement)
	import re as _re

	ansi = _re.compile(r'\x1b\[[0-9;]*m')

	def vis(s):
		return len(ansi.sub("", s))

	ellipsis = gray_desc("...")
	ell_w = vis(ellipsis)
	prefix = "  ←  "
	suffix = "  →"
	# usable width for the step tokens + separators
	budget = cols - len(prefix) - len(suffix) - 2

	# Find the widest window around `current` that fits. `current=None` has
	# no label of its own to anchor on, so use the last one (Confirm).
	anchor = current if current is not None else len(labels) - 1
	lo = anchor
	hi = anchor
	used = vis(rendered[anchor])

	# Expand outward greedily
	while True:
		grew = False
		if lo > 0:
			need = vis(rendered[lo - 1]) + len(sep) + (ell_w + len(sep) if lo - 1 > 0 else 0)
			if used + need <= budget:
				lo -= 1
				used += vis(rendered[lo]) + len(sep)
				grew = True
		if hi < len(rendered) - 1:
			need = vis(rendered[hi + 1]) + len(sep) + (ell_w + len(sep) if hi + 1 < len(rendered) - 1 else 0)
			if used + need <= budget:
				hi += 1
				used += vis(rendered[hi]) + len(sep)
				grew = True
		if not grew:
			break

	parts = []
	if lo > 0:
		parts.append(ellipsis)
	parts.extend(rendered[lo : hi + 1])
	if hi < len(rendered) - 1:
		parts.append(ellipsis)

	line = "─" * (cols - 2)
	print(f"\n{prefix}{sep.join(parts)}{suffix}")
	print(f"  {line}")


# ── Select component ──────────────────────────────────────────────────────────


def select_prompt(question, subtitle, options, current_value, revisit=False, validate_fn=None):
	"""
	options: list of (label, description, value)
	Returns selected value, or None on Esc.
	'__custom__' option activates an inline text editor.
	"""
	preset_values = {v for _, _, v in options if v != "__custom__"}
	custom_idx = next((i for i, (_, _, v) in enumerate(options) if v == "__custom__"), None)

	idx = 0
	for i, (_, _, v) in enumerate(options):
		if v == current_value:
			idx = i
			break
	if current_value and current_value not in preset_values and custom_idx is not None:
		idx = custom_idx

	editing = False
	edit_buf = list(current_value) if (current_value and current_value not in preset_values) else []
	edit_pos = len(edit_buf)
	err = ""

	def render(first=False):
		if first:
			print("\033[s", end="", flush=True)
		else:
			print("\033[u\033[J", end="", flush=True)

		out = []
		out.extend((f"  {bold(question)}", f"  {gray_desc(subtitle)}" if subtitle else "", ""))

		for i, (label, desc, value) in enumerate(options):
			is_custom = value == "__custom__"
			selected = i == idx
			num_s = gray_num(f"{i + 1}.")
			arrow = lavender("❯") if selected else " "

			if revisit and not is_custom:
				is_prior = value == current_value
				chk_prefix = (lavender("[✓]") if is_prior else gray_desc("[ ]")) + " "
			else:
				chk_prefix = ""

			if selected and editing and is_custom:
				s = "".join(edit_buf)
				before = s[:edit_pos]
				at = s[edit_pos : edit_pos + 1] or " "
				after = s[edit_pos + 1 :]
				lbl = f"{white_b(before)}\033[7m{at}\033[27m{white_b(after)}"
			elif is_custom and edit_buf:
				prefix = lavender("✎  ")
				val = lavender("".join(edit_buf), bold=True) if selected else white_b("".join(edit_buf))
				lbl = f"{prefix}{val}"
			elif selected:
				lbl = lavender(label, bold=True)
			else:
				lbl = white_b(label)

			out.append(f"  {arrow} {num_s} {chk_prefix}{lbl}")
			if is_custom and err:
				out.append(f"       {red('✗')} {gray_desc(err)}")
			elif desc:
				out.append(f"       {gray_desc(desc)}")

		out.extend(("", f"  {gray_desc(HINT_EDIT if editing else HINT_SEL)}"))

		text = "\n".join(out)
		print(text, end="\n", flush=True)

	print("\033[?25l", end="", flush=True)
	try:
		render(first=True)
		n_opts = len(options)
		with Raw():
			while True:
				k = read_key()

				if editing:
					if k == 'enter':
						value = "".join(edit_buf).strip()
						if value:
							if validate_fn:
								msg = validate_fn(value)
								if msg is not True:
									err = msg
								else:
									return value
							else:
								return value
						else:
							editing = False
							err = ""
					elif k == 'esc':
						editing = False
						err = ""
						edit_buf = list(current_value) if (current_value and current_value not in preset_values) else []
						edit_pos = len(edit_buf)
					elif k == 'ctrl_c':
						raise KeyboardInterrupt
					elif k == 'backspace' and edit_pos > 0:
						del edit_buf[edit_pos - 1]
						edit_pos -= 1
						err = ""
					elif k == 'left' and edit_pos > 0:
						edit_pos -= 1
					elif k == 'right' and edit_pos < len(edit_buf):
						edit_pos += 1
					elif k == 'home':
						edit_pos = 0
					elif k == 'end':
						edit_pos = len(edit_buf)
					elif isinstance(k, str) and len(k) == 1 and k.isprintable():
						edit_buf.insert(edit_pos, k)
						edit_pos += 1
						err = ""
				elif k in {'up', 'shift_tab'}:
					idx = (idx - 1) % n_opts
				elif k in {'down', 'tab'}:
					idx = (idx + 1) % n_opts
				elif k == 'enter':
					if options[idx][2] == '__custom__':
						editing = True
						edit_pos = len(edit_buf)
					else:
						return options[idx][2]
				elif k == 'esc':
					return None
				elif k == 'ctrl_c':
					raise KeyboardInterrupt
				elif k.isdigit() and 1 <= int(k) <= n_opts:
					target = int(k) - 1
					if options[target][2] == '__custom__':
						idx = target
						editing = True
						edit_pos = len(edit_buf)
					else:
						return options[target][2]

				render()
	finally:
		print("\033[?25h", end="", flush=True)


# ── Multi-select component ────────────────────────────────────────────────────


def multiselect_prompt(question, subtitle, options, current_values):
	"""
	Checkbox-style multi-select. Space toggles, Enter confirms.

	options:        list of (label, description, key)
	current_values: dict of {key: "true"/"false"}
	Returns dict of {key: "true"/"false"}, or None on Esc.
	"""
	selected = {key: current_values.get(key, "false") == "true" for _, _, key in options}
	idx = 0

	def render(first=False):
		if first:
			print("\033[s", end="", flush=True)
		else:
			print("\033[u\033[J", end="", flush=True)

		out = []
		out.extend((f"  {bold(question)}", f"  {gray_desc(subtitle)}" if subtitle else "", ""))

		for i, (label, desc, key) in enumerate(options):
			is_sel = i == idx
			arrow = lavender("❯") if is_sel else " "
			num_s = gray_num(f"{i + 1}.")
			chk = lavender("[✓]") if selected[key] else gray_desc("[ ]")
			lbl = lavender(label, bold=True) if is_sel else white_b(label)
			out.append(f"  {arrow} {num_s} {chk} {lbl}")
			if desc:
				out.append(f"       {gray_desc(desc)}")

		out.extend(("", f"  {gray_desc(HINT_MULTI)}"))

		text = "\n".join(out)
		print(text, end="\n", flush=True)

	print("\033[?25l", end="", flush=True)
	try:
		render(first=True)
		n_opts = len(options)
		with Raw():
			while True:
				k = read_key()
				if k in {'up', 'shift_tab'}:
					idx = (idx - 1) % n_opts
				elif k in {'down', 'tab'}:
					idx = (idx + 1) % n_opts
				elif k == ' ':
					selected[options[idx][2]] = not selected[options[idx][2]]
				elif k == 'enter':
					return {key: ("true" if v else "false") for key, v in selected.items()}
				elif k == 'esc':
					return None
				elif k == 'ctrl_c':
					raise KeyboardInterrupt
				elif k.isdigit() and 1 <= int(k) <= n_opts:
					key = options[int(k) - 1][2]
					selected[key] = not selected[key]
				render()
	finally:
		print("\033[?25h", end="", flush=True)


# ── Text input component ──────────────────────────────────────────────────────


def text_prompt(question, subtitle, default="", validate_fn=None):
	"""Raw-mode line editor with cursor movement. Returns stripped string, or None on Esc."""
	buf = list(default)
	pos = len(buf)
	err = ""

	def render(first=False):
		if first:
			print("\033[s", end="", flush=True)
		else:
			print("\033[u\033[J", end="", flush=True)

		s = "".join(buf)
		before = s[:pos]
		at = s[pos : pos + 1] or " "
		after = s[pos + 1 :]
		out = [
			f"  {gray_desc(subtitle)}" if subtitle else "",
			"",
			f"  {lavender('❯')} {before}\033[7m{at}\033[27m{after}",
			f"  {red('✗')} {gray_desc(err)}" if err else "",
			"",
			f"  {gray_desc(HINT_TEXT)}",
		]
		text = "\n".join(out)
		print(text, flush=True)

	print(f"  {bold(question)}")
	print("\033[?25l", end="", flush=True)

	try:
		render(first=True)
		with Raw():
			while True:
				k = read_key()
				if k == 'enter':
					value = "".join(buf).strip() or default
					if validate_fn:
						result = validate_fn(value)
						if result is not True:
							err = result
							render()
							continue
					err = ""
					return value
				if k == 'esc':
					return None
				if k == 'ctrl_c':
					raise KeyboardInterrupt
				if k == 'backspace' and pos > 0:
					del buf[pos - 1]
					pos -= 1
					err = ""
				elif k == 'left' and pos > 0:
					pos -= 1
				elif k == 'right' and pos < len(buf):
					pos += 1
				elif k == 'home':
					pos = 0
				elif k == 'end':
					pos = len(buf)
				elif isinstance(k, str) and len(k) == 1 and k.isprintable():
					buf.insert(pos, k)
					pos += 1
					err = ""
				render()
	finally:
		print("\033[?25h\n", end="", flush=True)


# ── Filter input component ────────────────────────────────────────────────────


def filter_prompt(question, subtitle, options, default=""):
	"""
	Text input with live-filtered dropdown. Typing narrows a list of options;
	arrow-down moves focus into the list, any printable key moves it back.

	options: list of strings
	default: pre-filled value (returned on Enter with no change)
	Returns selected string, or None on Esc.
	"""
	buf = list(default)
	pos = len(buf)
	list_idx = -1  # -1 = text focused, 0+ = list focused
	err = ""
	options_set = set(options)

	def _matches():
		query = "".join(buf).lower()
		return [o for o in options if query in o.lower()] if query else []

	def render(matches, first=False):
		if first:
			print("\033[s", end="", flush=True)
		else:
			print("\033[u\033[J", end="", flush=True)

		out = []
		out.append(f"  {bold(question)}")
		if subtitle:
			out.append(f"  {gray_desc(subtitle)}")
		out.append("")

		s = "".join(buf)
		if list_idx == -1:
			before = s[:pos]
			at = s[pos : pos + 1] or " "
			after = s[pos + 1 :]
			out.append(f"  {lavender('❯')} {before}\033[7m{at}\033[27m{after}")
		else:
			out.append(f"  {lavender('❯')} {gray_desc(s)}")

		if err:
			out.append(f"  {red('✗')} {gray_desc(err)}")

		shown = matches[:_FILTER_MAX]
		overflow = len(matches) - _FILTER_MAX
		if shown:
			out.append("")
			for i, m in enumerate(shown):
				if i == list_idx:
					out.append(f"  {lavender('❯')} {lavender(m, bold=True)}")
				else:
					out.append(f"    {white_b(m)}")
			if overflow > 0:
				out.append(f"    {gray_desc(f'... {overflow} more')}")
		elif s and not err:
			out.extend(("", f"    {gray_desc('no matches')}"))

		out.extend(("", f"  {gray_desc(HINT_FLIST if list_idx >= 0 else HINT_FILTER)}"))

		text = "\n".join(out)
		print(text, end="\n", flush=True)

	print("\033[?25l", end="", flush=True)
	try:
		matches = _matches()
		render(matches, first=True)
		with Raw():
			while True:
				k = read_key()
				matches = _matches()

				if list_idx == -1:
					if k == 'enter':
						value = "".join(buf).strip() or default
						if value in options_set:
							return value
						if len(matches) == 1:
							return matches[0]
						err = "Not found - try e.g. America/New_York or Europe/London" if not matches else f"Type more to narrow down ({len(matches)} matches)"
					elif k == 'down' and matches:
						list_idx = 0
						err = ""
					elif k == 'esc':
						return None
					elif k == 'ctrl_c':
						raise KeyboardInterrupt
					elif k == 'backspace' and pos > 0:
						del buf[pos - 1]
						pos -= 1
						err = ""
					elif k == 'left' and pos > 0:
						pos -= 1
					elif k == 'right' and pos < len(buf):
						pos += 1
					elif k == 'home':
						pos = 0
					elif k == 'end':
						pos = len(buf)
					elif isinstance(k, str) and len(k) == 1 and k.isprintable():
						buf.insert(pos, k)
						pos += 1
						err = ""
				else:
					shown_count = min(len(matches), _FILTER_MAX)
					if k == 'enter' and 0 <= list_idx < len(matches):
						return matches[list_idx]
					if k in {'up', 'shift_tab'}:
						list_idx = -1 if list_idx == 0 else list_idx - 1
					elif k in {'down', 'tab'}:
						if list_idx < shown_count - 1:
							list_idx += 1
					elif k == 'esc':
						list_idx = -1
					elif k == 'ctrl_c':
						raise KeyboardInterrupt
					elif isinstance(k, str) and len(k) == 1 and k.isprintable():
						list_idx = -1
						buf.insert(pos, k)
						pos += 1
						err = ""
					elif k == 'backspace':
						list_idx = -1
						if pos > 0:
							del buf[pos - 1]
							pos -= 1
						err = ""

				matches = _matches()
				# Clamp list cursor if matches shrank (e.g. user typed more)
				if list_idx >= min(len(matches), _FILTER_MAX):
					list_idx = max(-1, min(len(matches), _FILTER_MAX) - 1)
				render(matches)
	finally:
		print("\033[?25h\n", end="", flush=True)


# ── Password input component ──────────────────────────────────────────────────


def password_prompt(question, subtitle="", validate_fn=None):
	"""Masked password input - shows ● for each character. Returns string or None on Esc."""
	buf = []
	err = ""

	def render(first=False):
		if first:
			print("\033[s", end="", flush=True)
		else:
			print("\033[u\033[J", end="", flush=True)
		masked = "●" * len(buf)
		out = [
			f"  {gray_desc(subtitle)}" if subtitle else "",
			"",
			f"  {lavender('❯')} {masked}\033[7m \033[27m",
			f"  {red('✗')} {gray_desc(err)}" if err else "",
			"",
			f"  {gray_desc(HINT_PW)}",
		]
		text = "\n".join(out)
		print(text, flush=True)

	print(f"  {bold(question)}")
	print("\033[?25l", end="", flush=True)
	try:
		render(first=True)
		with Raw():
			while True:
				k = read_key()
				if k == 'enter':
					value = "".join(buf)
					if validate_fn:
						result = validate_fn(value)
						if result is not True:
							err = result
							render()
							continue
					return value
				if k == 'esc':
					return None
				if k == 'ctrl_c':
					raise KeyboardInterrupt
				if k == 'backspace' and buf:
					buf.pop()
					err = ""
				elif isinstance(k, str) and len(k) == 1 and k.isprintable():
					buf.append(k)
					err = ""
				render()
	finally:
		print("\033[?25h\n", end="", flush=True)
