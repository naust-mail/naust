"""Shared wizard orchestration - step runner, confirm screen, first-user flow."""

import os
import sys
from .ui import (
	bold,
	lavender,
	white_b,
	gray_desc,
	clear,
	nav,
	_term_width,
)


def _line():
	return "─" * (_term_width() - 2)


def confirm_screen(active, answers, value_display=None, all_steps=None, editable_keys=None):
	"""
	Summary screen showing all collected answers.

	All rows are navigable - pressing Enter on a row jumps back to edit that
	specific step, then returns here. Esc goes back to the previous step.

	active:        list of (key, label, fn) - steps asked this run
	answers:       full answers dict including values loaded from existing conf
	all_steps:     full STEPS list; if provided, shows every step that has a value
	value_display: optional dict mapping key -> {raw_value -> display_value}
	editable_keys: set of keys the user may edit from the confirm screen.
	               Defaults to active_keys (steps asked this run). Pass a wider
	               set to allow editing of profile-preset values.

	Returns:
	  True            - user confirmed, proceed
	  None            - Esc pressed, go back one step
	  ("edit", key)   - user wants to re-answer the step for this key
	"""
	from .ui import read_key, Raw

	display_steps = all_steps or active
	rows = []  # (key, label, display_val, is_editable)
	active_keys = {key for key, _, _ in active}
	if editable_keys is None:
		editable_keys = active_keys
	for key, label, *_ in display_steps:
		val = answers.get(key, "")
		if not val and key not in active_keys:
			continue
		if isinstance(val, dict):
			enabled = [k.replace("ENABLE_", "").title() for k, v in val.items() if v == "true"]
			val = ", ".join(enabled) if enabled else "None"
		elif value_display:
			val = value_display.get(key, {}).get(val, val)
		rows.append((key, label, val, key in editable_keys))

	# Navigable items: each config row + the "Confirm" action at the bottom.
	n_items = len(rows) + 1
	CONFIRM_IDX = len(rows)
	sel = CONFIRM_IDX  # start cursor on Confirm
	col_w = max((len(r[1]) for r in rows), default=10) + 2

	def render(first=False):
		if first:
			print("\033[s", end="", flush=True)
		else:
			print("\033[u\033[J", end="", flush=True)

		out = []
		out.extend((f"  {bold('Review your configuration')}", f"  {gray_desc('Navigate to edit a value, or confirm to continue.')}", ""))

		for i, (_key, label, val, is_active) in enumerate(rows):
			pad = " " * (col_w - len(label) - 1)
			if i == sel:
				out.append(f"  {lavender('❯')} {gray_desc(label + ':')}{pad}{lavender(val or '(none)', bold=True)}")
			else:
				display = white_b(val) if (val and is_active) else gray_desc(val or "(none)")
				out.append(f"    {gray_desc(label + ':')}{pad}{display}")

		out.append("")
		if sel == CONFIRM_IDX:
			out.append(f"  {lavender('❯')} {lavender('Confirm and continue', bold=True)}")
		else:
			out.append(f"    {white_b('Confirm and continue')}")

		out.extend(("", f"  {gray_desc('↑↓ navigate  ·  Enter to edit / confirm  ·  Esc to go back')}"))

		text = "\n".join(out)
		print(text, end="\n", flush=True)

	print("\033[?25l", end="", flush=True)
	try:
		render(first=True)
		with Raw():
			while True:
				k = read_key()
				if k in {'up', 'shift_tab'}:
					sel = (sel - 1) % n_items
				elif k in {'down', 'tab'}:
					sel = (sel + 1) % n_items
				elif k == 'enter':
					if sel == CONFIRM_IDX:
						return True
					key = rows[sel][0]
					if key in editable_keys:
						return ("edit", key)
					# Gray (non-editable) rows: ignore Enter.
				elif k == 'esc':
					return None
				elif k == 'ctrl_c':
					raise KeyboardInterrupt
				render()
	finally:
		print("\033[?25h", end="", flush=True)


def run_questions(steps, args, value_display=None, initial=None, all_steps=None, all_editable=False):
	"""
	Run a wizard flow over a list of steps.

	steps:        list of (key, label, fn) - steps shown interactively this run
	args:         passed through to each step function
	value_display: optional dict for confirm_screen display formatting
	initial:      optional dict of pre-populated answers (e.g. loaded from .env)
	all_steps:    full step list for the confirm screen display
	all_editable: if True, every step in all_steps is editable on the confirm
	              screen, not just the ones asked this run. Used for profile installs
	              where presets are pre-filled but the user can still change anything.

	Returns dict of answers, or exits on cancellation.
	"""
	if not steps:
		return {}

	labels = [label for _, label, _ in steps] + ["Confirm"]
	answers = dict(initial) if initial else {}
	done = set()
	idx = 0

	while idx <= len(steps):
		clear()
		nav(labels, idx, done)
		print()

		if idx == len(steps):
			editable = None
			if all_editable and all_steps:
				editable = {key for key, _, _ in all_steps}
			try:
				result = confirm_screen(steps, answers, value_display, all_steps=all_steps, editable_keys=editable)
			except KeyboardInterrupt:
				clear()
				print("\n  Setup cancelled.\n")
				sys.exit(1)
			if result is True:
				break
			if isinstance(result, tuple) and result[0] == "edit":
				# User picked a specific row to re-answer. Run just that step,
				# then return to confirm regardless of what they entered.
				# For profile installs (all_editable), steps only contains the
				# hostname step - fall back to all_steps to find preset entries.
				edit_key = result[1]
				search_pool = steps
				step_idx = next((i for i, (k, _, _) in enumerate(search_pool) if k == edit_key), None)
				if step_idx is None and all_editable and all_steps:
					search_pool = all_steps
					step_idx = next((i for i, (k, _, _) in enumerate(search_pool) if k == edit_key), None)
				if step_idx is not None:
					_, _, fn = search_pool[step_idx]
					clear()
					# nav is indexed into the active steps labels; use None when
					# editing a step from all_steps that wasn't asked interactively.
					nav_idx = next((i for i, (k, _, _) in enumerate(steps) if k == edit_key), None)
					nav(labels, nav_idx, done)
					print()
					try:
						step_result = fn(args, answers)
					except KeyboardInterrupt:
						step_result = None
					if step_result is not None:
						if isinstance(step_result, dict):
							answers.update(step_result)
						answers[edit_key] = step_result
						done.add(step_idx)
				# idx stays at len(steps) - we return to confirm either way
			else:
				# Esc - go back to previous step
				idx -= 1
		else:
			key, _label, fn = steps[idx]
			try:
				result = fn(args, answers)
			except KeyboardInterrupt:
				clear()
				print("\n  Setup cancelled.\n")
				sys.exit(1)

			if result is None:
				if idx == 0:
					clear()
					print("\n  Setup cancelled.\n")
					sys.exit(1)
				done.discard(idx)
				idx -= 1
			else:
				if isinstance(result, dict):
					# Multi-select: merge individual keys into answers, keep
					# dict under step key so confirm_screen can display it.
					answers.update(result)
				answers[key] = result
				done.add(idx)
				idx += 1

	clear()
	return answers


def write_output(path, results):
	"""Write shell-sourceable key=value pairs (bare metal wizard output)."""

	def q(v):
		return "'" + v.replace("'", "'\\''") + "'"

	tmp = path + ".tmp"
	with open(tmp, "w", encoding="utf-8") as f:
		for k, v in results.items():
			if k.startswith("__") or isinstance(v, dict):
				continue  # sentinel keys from multi-select steps; real values already merged
			f.write(f"{k}={q(v)}\n")
	os.replace(tmp, path)


def load_conf(path):
	"""
	Parse a key=value config file into a dict.

	Handles both shell-quoted values (KEY='value' or KEY="value") written by
	write_output, and plain unquoted values (KEY=value) written by write_env.
	Skips comments and blank lines. Returns {} if the file does not exist.
	"""
	values = {}
	try:
		with open(path, encoding="utf-8") as f:
			for raw_line in f:
				line = raw_line.strip()
				if not line or line.startswith("#") or "=" not in line:
					continue
				k, _, v = line.partition("=")
				k = k.strip()
				v = v.strip()
				# Strip matching outer quotes
				if len(v) >= 2 and v[0] == v[-1] and v[0] in {"'", '"'}:
					v = v[1:-1]
				values[k] = v
	except FileNotFoundError:
		pass
	return values
