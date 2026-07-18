# SPDX-License-Identifier: GPL-3.0-or-later
"""
Radicale 3.7+ storage backend for Naust.

Bridges rav per-user SQLite databases to CardDAV/CalDAV:
  /<email>/contacts/  -> VADDRESSBOOK (contacts table)
  /<email>/calendar/  -> VCALENDAR (calendar_events table)

Database path: $RAV_DATA_DIR/<sha256(email)>/db.sqlite
"""

import hashlib
import logging
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from collections.abc import Iterable, Iterator, Mapping

from radicale import storage
from radicale.item import Item

logger = logging.getLogger(__name__)

_CONTACTS = "contacts"
_CALENDAR = "calendar"
_PRODID = "-//NAUST//rav//EN"

# Full queries keyed by collection type, rather than interpolating the table
# name into an f-string - the table is always one of these two fixed literals,
# never user input, but this avoids the pattern entirely instead of asserting so.
_SQL_MAX_UPDATED_AT = {
	_CONTACTS: "SELECT MAX(updated_at) as ts FROM contacts",
	_CALENDAR: "SELECT MAX(updated_at) as ts FROM calendar_events",
}
_SQL_SELECT_ID = {
	_CONTACTS: "SELECT id FROM contacts",
	_CALENDAR: "SELECT id FROM calendar_events",
}
_SQL_SELECT_ID_WHERE_ID = {
	_CONTACTS: "SELECT id FROM contacts WHERE id=?",
	_CALENDAR: "SELECT id FROM calendar_events WHERE id=?",
}

_user_locks: dict[str, threading.Lock] = {}
_locks_mutex = threading.Lock()


def _get_user_lock(user: str) -> threading.Lock:
	with _locks_mutex:
		if user not in _user_locks:
			_user_locks[user] = threading.Lock()
		return _user_locks[user]


def _hash_email(email: str) -> str:
	"""Match rav's hash_email: SHA-256 of raw email bytes, lowercase hex."""
	return hashlib.sha256(email.encode()).hexdigest()


def _db_path(data_dir: str, email: str) -> str:
	return os.path.join(data_dir, _hash_email(email), "db.sqlite")


def _open_db(data_dir: str, email: str) -> sqlite3.Connection | None:
	path = _db_path(data_dir, email)
	if not os.path.exists(path):
		return None
	conn = sqlite3.connect(path, timeout=5.0)
	conn.row_factory = sqlite3.Row
	conn.execute("PRAGMA foreign_keys=ON")
	conn.execute("PRAGMA journal_mode=WAL")
	return conn


def _ensure_columns(conn: sqlite3.Connection) -> None:
	"""Add Radicale storage columns to rav's tables if not present yet."""
	try:
		existing = {r[1] for r in conn.execute("PRAGMA table_info(contacts)")}
		if "vcard_data" not in existing:
			conn.execute("ALTER TABLE contacts ADD COLUMN vcard_data TEXT")
			conn.commit()
	except sqlite3.OperationalError:
		pass
	try:
		existing = {r[1] for r in conn.execute("PRAGMA table_info(calendar_events)")}
		if "ical_data" not in existing:
			conn.execute("ALTER TABLE calendar_events ADD COLUMN ical_data TEXT")
			conn.commit()
	except sqlite3.OperationalError:
		pass


def _vcard_escape(s: str) -> str:
	return s.replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\n", "\\n")


def _ical_escape(s: str) -> str:
	return s.replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\n", "\\n")


def _fold(line: str) -> str:
	if len(line) <= 75:
		return line
	parts = [line[:75]]
	rest = line[75:]
	while rest:
		parts.append(" " + rest[:74])
		rest = rest[74:]
	return "\r\n".join(parts)


def _now_sql() -> str:
	return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _last_modified_rfc1123(updated_at: str) -> str:
	try:
		s = updated_at.replace("T", " ").rstrip("Z")
		dt = datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
		return dt.strftime("%a, %d %b %Y %H:%M:%S GMT")
	except (ValueError, AttributeError):
		return datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")


def _dt_to_ical(dt_str: str, all_day: bool = False) -> str:
	try:
		s = dt_str.replace("T", " ").rstrip("Z")
		if all_day:
			return datetime.strptime(s[:10], "%Y-%m-%d").strftime("%Y%m%d")
		return datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S").strftime("%Y%m%dT%H%M%SZ")
	except (ValueError, AttributeError):
		return ""


def _parse_ical_dt(val: str) -> str:
	val = val.strip().rstrip("Z")
	try:
		if "T" in val:
			return datetime.strptime(val[:15], "%Y%m%dT%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
		return datetime.strptime(val[:8], "%Y%m%d").strftime("%Y-%m-%d 00:00:00")
	except ValueError:
		return val


def _contact_to_vcard(row: sqlite3.Row) -> str:
	if row["vcard_data"]:
		return row["vcard_data"]
	lines = ["BEGIN:VCARD", "VERSION:3.0", f"UID:{row['id']}"]
	name = _vcard_escape(row["name"] or "")
	email = row["email"] or ""
	if name:
		lines.append(_fold(f"FN:{name}"))
		parts = name.split(" ", 1)
		last = _vcard_escape(parts[-1]) if len(parts) > 1 else ""
		first = _vcard_escape(parts[0]) if len(parts) > 1 else _vcard_escape(name)
		lines.append(f"N:{last};{first};;;")
	else:
		lines.extend((f"FN:{email}", "N:;;;;"))
	if email:
		lines.append(f"EMAIL;TYPE=INTERNET:{_vcard_escape(email)}")
	if row["company"]:
		lines.append(_fold(f"ORG:{_vcard_escape(row['company'])}"))
	if row["notes"]:
		lines.append(_fold(f"NOTE:{_vcard_escape(row['notes'])}"))
	rev = (row["updated_at"] or "").replace(" ", "T").rstrip("Z") + "Z"
	lines.extend((f"REV:{rev}", "END:VCARD"))
	return "\r\n".join(lines) + "\r\n"


def _event_to_ical(row: sqlite3.Row) -> str:
	if row["ical_data"]:
		return row["ical_data"]
	all_day = bool(row["all_day"])
	start = _dt_to_ical(row["start_time"], all_day)
	end = _dt_to_ical(row["end_time"], all_day)
	dtstamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
	lines = [
		"BEGIN:VCALENDAR",
		"VERSION:2.0",
		f"PRODID:{_PRODID}",
		"CALSCALE:GREGORIAN",
		"BEGIN:VEVENT",
		f"UID:{row['id']}",
		f"DTSTAMP:{dtstamp}",
	]
	if all_day:
		lines += [f"DTSTART;VALUE=DATE:{start}", f"DTEND;VALUE=DATE:{end}"]
	else:
		lines += [f"DTSTART:{start}", f"DTEND:{end}"]
	if row["title"]:
		lines.append(_fold(f"SUMMARY:{_ical_escape(row['title'])}"))
	if row["description"]:
		lines.append(_fold(f"DESCRIPTION:{_ical_escape(row['description'])}"))
	if row["location"]:
		lines.append(_fold(f"LOCATION:{_ical_escape(row['location'])}"))
	if row["recurrence_rule"]:
		lines.append(f"RRULE:{row['recurrence_rule']}")
	if row["status"]:
		lines.append(f"STATUS:{row['status'].upper()}")
	lines += ["END:VEVENT", "END:VCALENDAR"]
	return "\r\n".join(lines) + "\r\n"


def _parse_vcard(text: str) -> dict:
	fields = {"name": "", "email": "", "company": "", "notes": ""}
	unfolded = text.replace("\r\n ", "").replace("\r\n\t", "")
	for line in unfolded.splitlines():
		key, _, value = line.partition(":")
		key_base = key.upper().split(";")[0]
		value = value.replace("\\n", "\n").replace("\\,", ",").replace("\\;", ";").replace("\\\\", "\\")
		if key_base == "FN":
			fields["name"] = value
		elif key_base == "EMAIL" and not fields["email"]:
			fields["email"] = value
		elif key_base == "ORG":
			fields["company"] = value.split(";")[0]
		elif key_base == "NOTE":
			fields["notes"] = value
	return fields


def _parse_ical(text: str) -> dict:
	fields = {
		"title": "",
		"description": "",
		"location": "",
		"start_time": "",
		"end_time": "",
		"all_day": 0,
		"recurrence_rule": None,
		"status": "confirmed",
	}
	in_vevent = False
	unfolded = text.replace("\r\n ", "").replace("\r\n\t", "")
	for line in unfolded.splitlines():
		if line == "BEGIN:VEVENT":
			in_vevent = True
			continue
		if line == "END:VEVENT":
			break
		if not in_vevent:
			continue
		key, _, value = line.partition(":")
		key_base = key.upper().split(";")[0]
		value = value.replace("\\n", "\n").replace("\\,", ",").replace("\\;", ";").replace("\\\\", "\\")
		if key_base == "SUMMARY":
			fields["title"] = value
		elif key_base == "DESCRIPTION":
			fields["description"] = value
		elif key_base == "LOCATION":
			fields["location"] = value
		elif key_base == "RRULE":
			fields["recurrence_rule"] = value
		elif key_base == "STATUS":
			fields["status"] = value.lower()
		elif key_base in {"DTSTART", "DTEND"}:
			if "VALUE=DATE" in key.upper() and "VALUE=DATE-TIME" not in key.upper():
				fields["all_day"] = 1
			parsed = _parse_ical_dt(value)
			if key_base == "DTSTART":
				fields["start_time"] = parsed
			else:
				fields["end_time"] = parsed
	return fields


class _RootCollection(storage.BaseCollection):
	"""Synthetic root collection returned for path '/' to allow client discovery."""

	@property
	def path(self) -> str:
		return ""

	@property
	def tag(self) -> str:
		return ""

	@property
	def etag(self) -> str:
		return '"root"'

	@property
	def last_modified(self) -> str:
		return datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

	def get_meta(self, key=None):
		meta: dict = {"D:displayname": "Radicale"}
		return meta.get(key) if key else meta

	def set_meta(self, props) -> None:
		pass

	def get_all(self) -> Iterator[Item]:
		return iter([])

	def get_multi(self, hrefs) -> Iterable[tuple[str, Item | None]]:
		return iter([])

	def get_filtered(self, filters) -> Iterable[tuple[Item, bool]]:
		return iter([])

	def has_uid(self, uid: str) -> bool:
		return False

	def serialize(self, vcf_to_ics: bool = False, **kwargs) -> str:
		return ""

	def sync(self, old_token: str = "") -> tuple[str, Iterable[str]]:
		return '"root"', []

	def upload(self, href: str, item: Item) -> tuple[Item, Item | None]:
		raise NotImplementedError

	def delete(self, href: str | None = None) -> None:
		pass


class _RavCollection(storage.BaseCollection):
	def __init__(self, path: str, data_dir: str, email: str, coll_type: str):
		self._path = path
		self._data_dir = data_dir
		self._email = email
		self._type = coll_type
		self._db = _open_db(data_dir, email)
		if self._db is not None:
			_ensure_columns(self._db)

	@property
	def path(self) -> str:
		return self._path

	@property
	def tag(self) -> str:
		return "VADDRESSBOOK" if self._type == _CONTACTS else "VCALENDAR"

	@property
	def color(self) -> str:
		return ""

	@property
	def is_principal(self) -> bool:
		return False

	@property
	def owner(self) -> str:
		return self._email

	@property
	def etag(self) -> str:
		if self._db is None:
			return '"empty"'
		try:
			row = self._db.execute(_SQL_MAX_UPDATED_AT[self._type]).fetchone()
			ts = row["ts"] or "empty"
			return f'"{hashlib.md5(ts.encode(), usedforsecurity=False).hexdigest()}"'
		except sqlite3.OperationalError:
			return '"empty"'

	@property
	def last_modified(self) -> str:
		if self._db is None:
			return datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
		try:
			row = self._db.execute(_SQL_MAX_UPDATED_AT[self._type]).fetchone()
			ts = row["ts"] if row and row["ts"] else _now_sql()
			return _last_modified_rfc1123(ts)
		except sqlite3.OperationalError:
			return datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

	def get_meta(self, key: str | None = None):
		meta = {"tag": "VADDRESSBOOK", "D:displayname": "Contacts", "CR:addressbook-description": "rav contacts"} if self._type == _CONTACTS else {"tag": "VCALENDAR", "D:displayname": "Calendar", "C:calendar-description": "rav calendar"}
		return meta.get(key) if key else meta

	def set_meta(self, props: Mapping) -> None:
		pass

	def get(self, href: str) -> Item | None:
		if self._db is None:
			return None
		uid = href.rsplit(".", 1)[0]
		try:
			if self._type == _CONTACTS:
				row = self._db.execute("SELECT id, email, name, company, notes, vcard_data, updated_at FROM contacts WHERE id=?", (uid,)).fetchone()
				if row is None:
					return None
				text = _contact_to_vcard(row)
				lm = _last_modified_rfc1123(row["updated_at"])
			else:
				row = self._db.execute("SELECT id, title, description, location, start_time, end_time, all_day, recurrence_rule, status, ical_data, updated_at FROM calendar_events WHERE id=?", (uid,)).fetchone()
				if row is None:
					return None
				text = _event_to_ical(row)
				lm = _last_modified_rfc1123(row["updated_at"])
			return Item(collection=self, collection_path=self._path, href=href, last_modified=lm, text=text)
		except sqlite3.OperationalError:
			return None

	def get_all(self) -> Iterator[Item]:
		if self._db is None:
			return
		try:
			if self._type == _CONTACTS:
				rows = self._db.execute("SELECT id, email, name, company, notes, vcard_data, updated_at FROM contacts").fetchall()
				for row in rows:
					yield Item(collection=self, collection_path=self._path, href=f"{row['id']}.vcf", last_modified=_last_modified_rfc1123(row["updated_at"]), text=_contact_to_vcard(row))
			else:
				rows = self._db.execute("SELECT id, title, description, location, start_time, end_time, all_day, recurrence_rule, status, ical_data, updated_at FROM calendar_events").fetchall()
				for row in rows:
					yield Item(collection=self, collection_path=self._path, href=f"{row['id']}.ics", last_modified=_last_modified_rfc1123(row["updated_at"]), text=_event_to_ical(row))
		except sqlite3.OperationalError:
			return

	def get_multi(self, hrefs: Iterable[str]) -> Iterable[tuple[str, Item | None]]:
		for href in hrefs:
			yield href, self.get(href)

	def get_filtered(self, filters) -> Iterable[tuple[Item, bool]]:
		for item in self.get_all():
			yield item, True

	def has_uid(self, uid: str) -> bool:
		if self._db is None:
			return False
		try:
			row = self._db.execute(_SQL_SELECT_ID_WHERE_ID[self._type], (uid,)).fetchone()
		except sqlite3.OperationalError:
			return False
		else:
			return row is not None

	def serialize(self, vcf_to_ics: bool = False, **kwargs) -> str:
		return "".join(item.serialize() for item in self.get_all())

	def sync(self, old_token: str = "") -> tuple[str, Iterable[str]]:
		token = self.etag
		if self._db is None:
			return token, []
		try:
			ext = ".vcf" if self._type == _CONTACTS else ".ics"
			rows = self._db.execute(_SQL_SELECT_ID[self._type]).fetchall()
			hrefs = [f"{row['id']}{ext}" for row in rows]
		except sqlite3.OperationalError:
			return token, []
		else:
			return token, hrefs

	def upload(self, href: str, item: Item) -> tuple[Item, Item | None]:
		old_item = self.get(href)
		uid = href.rsplit(".", 1)[0]
		text = item.serialize()
		now = _now_sql()
		if self._db is None:
			msg = "No rav database found for user - log into rav first"
			raise RuntimeError(msg)
		if self._type == _CONTACTS:
			f = _parse_vcard(text)
			try:
				self._db.execute(
					"""
                    INSERT INTO contacts
                        (id, email, name, company, notes, vcard_data, source, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, 'radicale', ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        email=excluded.email, name=excluded.name,
                        company=excluded.company, notes=excluded.notes,
                        vcard_data=excluded.vcard_data, updated_at=excluded.updated_at
                """,
					(uid, f["email"], f["name"], f["company"], f["notes"], text, now, now),
				)
				self._db.commit()
			except sqlite3.IntegrityError:
				self._db.execute(
					"""
                    UPDATE contacts SET name=?, company=?, notes=?, vcard_data=?, updated_at=?
                    WHERE email=?
                """,
					(f["name"], f["company"], f["notes"], text, now, f["email"]),
				)
				self._db.commit()
		else:
			f = _parse_ical(text)
			self._db.execute(
				"""
                INSERT INTO calendar_events
                    (id, title, description, location, start_time, end_time,
                     all_day, recurrence_rule, status, ical_data, source, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'radicale', ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    title=excluded.title, description=excluded.description,
                    location=excluded.location, start_time=excluded.start_time,
                    end_time=excluded.end_time, all_day=excluded.all_day,
                    recurrence_rule=excluded.recurrence_rule, status=excluded.status,
                    ical_data=excluded.ical_data, updated_at=excluded.updated_at
            """,
				(uid, f["title"], f["description"], f["location"], f["start_time"], f["end_time"], f["all_day"], f["recurrence_rule"], f["status"], text, now, now),
			)
			self._db.commit()
		lm = _last_modified_rfc1123(now)
		new_item = Item(collection=self, collection_path=self._path, href=href, last_modified=lm, text=text)
		return new_item, old_item

	def delete(self, href: str | None = None) -> None:
		if href is None or self._db is None:
			return
		uid = href.rsplit(".", 1)[0]
		try:
			if self._type == _CONTACTS:
				self._db.execute("DELETE FROM contacts WHERE id=?", (uid,))
			else:
				self._db.execute("DELETE FROM calendar_events WHERE id=?", (uid,))
			self._db.commit()
		except sqlite3.OperationalError:
			pass


class _PrincipalCollection(storage.BaseCollection):
	"""Per-user principal collection."""

	def __init__(self, path: str, email: str):
		self._path = path
		self._email = email

	@property
	def path(self) -> str:
		return self._path

	@property
	def tag(self) -> str:
		return ""

	@property
	def is_principal(self) -> bool:
		return True

	@property
	def owner(self) -> str:
		return self._email

	@property
	def etag(self) -> str:
		return f'"{hashlib.md5(self._email.encode(), usedforsecurity=False).hexdigest()}"'

	@property
	def last_modified(self) -> str:
		return datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

	def get_meta(self, key: str | None = None):
		meta = {"D:displayname": self._email}
		return meta.get(key) if key else meta

	def set_meta(self, props: Mapping) -> None:
		pass

	def get(self, href: str) -> Item | None:
		return None

	def get_all(self) -> Iterator[Item]:
		return iter([])

	def get_multi(self, hrefs: Iterable[str]) -> Iterable[tuple[str, Item | None]]:
		for href in hrefs:
			yield href, None

	def get_filtered(self, filters) -> Iterable[tuple[Item, bool]]:
		return iter([])

	def has_uid(self, uid: str) -> bool:
		return False

	def serialize(self, vcf_to_ics: bool = False, **kwargs) -> str:
		return ""

	def sync(self, old_token: str = "") -> tuple[str, Iterable[str]]:
		return self.etag, []

	def upload(self, href: str, item: Item) -> tuple[Item, Item | None]:
		raise NotImplementedError

	def delete(self, href: str | None = None) -> None:
		pass


class Storage(storage.BaseStorage):
	def __init__(self, configuration):
		super().__init__(configuration)
		self._data_dir = os.environ.get("RAV_DATA_DIR", "")
		if not self._data_dir:
			msg = "RAV_DATA_DIR environment variable is not set"
			raise RuntimeError(msg)

	@contextmanager
	def acquire_lock(self, mode: str, user: str = "", *args, **kwargs):
		lock = _get_user_lock(user or "")
		lock.acquire()
		try:
			yield
		finally:
			lock.release()

	def _parse_path(self, path: str):
		parts = [p for p in path.strip("/").split("/") if p]
		if not parts:
			return None, None, None
		email = parts[0]
		if len(parts) == 1:
			return email, None, None
		coll = parts[1]
		href = parts[2] if len(parts) > 2 else None
		if coll == _CONTACTS:
			return email, _CONTACTS, href
		if coll == _CALENDAR:
			return email, _CALENDAR, href
		return email, None, None

	def _collection(self, email: str, coll_type: str) -> _RavCollection:
		return _RavCollection(f"{email}/{coll_type}", self._data_dir, email, coll_type)

	def discover(self, path: str, depth: str = "0", child_context_manager=None, user_groups=None) -> Iterable:
		email, coll_type, href = self._parse_path(path)
		if email is None:
			yield _RootCollection()
			return
		if coll_type is None:
			yield _PrincipalCollection(email, email)
			if depth != "0":
				yield self._collection(email, _CONTACTS)
				yield self._collection(email, _CALENDAR)
			return
		coll = self._collection(email, coll_type)
		yield coll
		if depth != "0" and href is None:
			yield from coll.get_all()

	def move(self, item: Item, to_collection, to_href: str) -> None:
		to_collection.upload(to_href, item)
		item.collection.delete(item.href)

	def create_collection(self, href: str, items=None, props=None) -> tuple[storage.BaseCollection, dict, list]:
		email, coll_type, _ = self._parse_path(href)
		sane = href.strip("/")
		coll = _RavCollection(sane, self._data_dir, email, coll_type) if coll_type else _PrincipalCollection(sane, email)
		return coll, {}, []

	def get_collection(self, path: str) -> storage.BaseCollection | None:
		email, coll_type, _ = self._parse_path(path)
		if email is None:
			return None
		if coll_type is None:
			return _PrincipalCollection(email, email)
		return self._collection(email, coll_type)

	def verify(self) -> bool:
		return True
