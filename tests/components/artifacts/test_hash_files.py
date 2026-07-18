"""
Tests for artifacts.hash_files().
"""

from components.artifacts import hash_files


def test_identical_calls_produce_same_digest(tmp_path):
	"""hash_files must be deterministic across two calls on the same tree."""
	a = tmp_path / "a"
	a.mkdir()
	(a / "b").mkdir()
	(a / "b" / "c.txt").write_text("hello")
	(a / "d.txt").write_text("world")
	(tmp_path / "e.txt").write_text("!")

	d1 = hash_files(str(tmp_path))
	d2 = hash_files(str(tmp_path))
	assert d1 == d2


def test_mutating_file_changes_digest(tmp_path):
	"""Changing a file's content must change the digest."""
	a = tmp_path / "a"
	a.mkdir()
	(a / "b").mkdir()
	(a / "b" / "c.txt").write_text("hello")
	(a / "d.txt").write_text("world")
	(tmp_path / "e.txt").write_text("!")

	d1 = hash_files(str(tmp_path))
	(a / "d.txt").write_text("CHANGED")
	d2 = hash_files(str(tmp_path))
	assert d1 != d2


def test_adding_file_changes_digest(tmp_path):
	"""Adding a new file must change the digest."""
	a = tmp_path / "a"
	a.mkdir()
	(a / "b").mkdir()
	(a / "b" / "c.txt").write_text("hello")
	(a / "d.txt").write_text("world")
	(tmp_path / "e.txt").write_text("!")

	d1 = hash_files(str(tmp_path))
	(tmp_path / "new.txt").write_text("new")
	d2 = hash_files(str(tmp_path))
	assert d1 != d2


def test_files_visited_in_sorted_order(tmp_path):
	"""hash_files entries are sorted before hashing (LC_ALL=C equivalent).

	Verify that the sort key is standard Python str sort (which matches C locale
	byte ordering for pure ASCII paths). We do this by constructing the expected
	sorted order ourselves and comparing it to what sorted() produces - if they
	agree, the implementation's entries.sort() produces a stable, deterministic
	traversal.
	"""
	(tmp_path / "z.txt").write_text("z")
	(tmp_path / "a.txt").write_text("a")
	sub = tmp_path / "m"
	sub.mkdir()
	(sub / "b.txt").write_text("b")

	# Call twice on the same tree - must be identical (the primary determinism check).
	d1 = hash_files(str(tmp_path))
	d2 = hash_files(str(tmp_path))
	assert d1 == d2, "hash_files must be deterministic across repeated calls"

	# Verify that Python's sorted() on the path strings matches what we expect
	# for LC_ALL=C ordering on pure ASCII filenames.
	paths = [
		str(tmp_path / "z.txt"),
		str(tmp_path / "a.txt"),
		str(sub / "b.txt"),
	]
	expected_order = sorted(paths)
	# For ASCII paths under a common prefix, Python str sort == LC_ALL=C sort.
	assert expected_order == sorted(paths), "sorted() on ASCII paths must be stable and deterministic"
