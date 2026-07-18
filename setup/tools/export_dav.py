#!/usr/bin/env python3
"""
Export CalDAV/CardDAV data for all users to a directory of standard vCard and iCal files.

Supports two storage backends:
  - rav (default): reads per-user SQLite databases from $RAV_DATA_DIR
  - multifilesystem: copies files from /var/lib/radicale/collections/

Usage:
  sudo python3 setup/tools/export_dav.py [--output DIR] [--storage rav|files]

Output layout:
  <DIR>/
    user@domain.com/
      contacts.vcf      (all contacts as a single vCard file)
      calendar.ics      (all events as a single iCal file)

The output files can be imported directly into Nextcloud via its web interface
under Contacts > Import and Calendar > Import.

Run as root - the rav database files are owned by www-data.
"""

import argparse
import hashlib
import os
import pathlib
import sqlite3
import sys
from datetime import datetime, timezone

_PRODID = "-//NAUST//rav//EN"


# ---------------------------------------------------------------------------
# Helpers (duplicated from radicale_naust/storage.py to keep this standalone)
# ---------------------------------------------------------------------------


def _hash_email(email: str) -> str:
	return hashlib.sha256(email.encode()).hexdigest()


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


def _dt_to_ical(dt_str: str, all_day: bool = False) -> str:
	try:
		s = (dt_str or "").replace("T", " ").rstrip("Z")
		if all_day:
			return datetime.strptime(s[:10], "%Y-%m-%d").strftime("%Y%m%d")
		return datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S").strftime("%Y%m%dT%H%M%SZ")
	except (ValueError, AttributeError):
		return ""


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


# ---------------------------------------------------------------------------
# Export: rav SQLite backend
# ---------------------------------------------------------------------------


def _export_rav(rav_data_dir: str, users_db: str, output_dir: str) -> None:
	"""Export from rav per-user SQLite databases."""
	# Get all known email addresses from the users database.
	conn = sqlite3.connect(users_db)
	conn.row_factory = sqlite3.Row
	emails = [r["email"] for r in conn.execute("SELECT email FROM users").fetchall()]
	conn.close()

	exported = 0
	for email in emails:
		db_path = os.path.join(rav_data_dir, _hash_email(email), "db.sqlite")
		if not os.path.exists(db_path):
			print(f"  skip {email}: no rav database (user has never logged into rav)")
			continue

		db = sqlite3.connect(db_path)
		db.row_factory = sqlite3.Row

		user_dir = os.path.join(output_dir, email)
		os.makedirs(user_dir, exist_ok=True)

		# Contacts
		try:
			rows = db.execute("SELECT id, email, name, company, notes, vcard_data, updated_at FROM contacts").fetchall()
			if rows:
				vcf_path = os.path.join(user_dir, "contacts.vcf")
				with open(vcf_path, "w", encoding="utf-8") as f:
					f.writelines(_contact_to_vcard(row) for row in rows)
				print(f"  {email}: {len(rows)} contact(s)")
		except sqlite3.OperationalError:
			pass  # table doesn't exist yet for this user

		# Calendar events
		try:
			rows = db.execute("SELECT id, title, description, location, start_time, end_time, all_day, recurrence_rule, status, ical_data, updated_at FROM calendar_events").fetchall()
			if rows:
				ics_path = os.path.join(user_dir, "calendar.ics")
				with open(ics_path, "w", encoding="utf-8") as f:
					f.writelines(_event_to_ical(row) for row in rows)
				print(f"  {email}: {len(rows)} calendar event(s)")
		except sqlite3.OperationalError:
			pass

		db.close()
		exported += 1

	print(f"\nExported data for {exported} user(s) to {output_dir}")


# ---------------------------------------------------------------------------
# Export: Radicale multifilesystem backend
# ---------------------------------------------------------------------------


def _export_files(radicale_collections_dir: str, output_dir: str) -> None:
	"""Export from Radicale multifilesystem storage.
	Files are already standard vCard/iCal - just copy and consolidate them."""
	if not os.path.isdir(radicale_collections_dir):
		print(f"Error: {radicale_collections_dir} does not exist.", file=sys.stderr)
		sys.exit(1)

	exported = 0
	for entry in sorted(os.scandir(radicale_collections_dir), key=lambda e: e.name):
		if not entry.is_dir():
			continue
		email = entry.name

		contacts_dir = os.path.join(entry.path, "contacts")
		calendar_dir = os.path.join(entry.path, "calendar")

		user_dir = os.path.join(output_dir, email)
		os.makedirs(user_dir, exist_ok=True)

		if os.path.isdir(contacts_dir):
			vcf_files = [f for f in os.scandir(contacts_dir) if f.name.endswith(".vcf")]
			if vcf_files:
				vcf_out = os.path.join(user_dir, "contacts.vcf")
				with open(vcf_out, "w", encoding="utf-8") as out:
					out.writelines(pathlib.Path(vcf.path).read_text(encoding="utf-8") for vcf in vcf_files)
				print(f"  {email}: {len(vcf_files)} contact(s)")

		if os.path.isdir(calendar_dir):
			ics_files = [f for f in os.scandir(calendar_dir) if f.name.endswith(".ics")]
			if ics_files:
				ics_out = os.path.join(user_dir, "calendar.ics")
				with open(ics_out, "w", encoding="utf-8") as out:
					out.writelines(pathlib.Path(ics.path).read_text(encoding="utf-8") for ics in ics_files)
				print(f"  {email}: {len(ics_files)} calendar event(s)")

		exported += 1

	print(f"\nExported data for {exported} user(s) to {output_dir}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
	parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument("--output", default="/tmp/dav-export", help="Directory to write export files to (default: /tmp/dav-export)")  # noqa: S108 - discoverable default export destination for the operator, not a scratch file
	parser.add_argument("--storage", choices=["rav", "files"], default="rav", help="Storage backend: rav (default) or files (multifilesystem)")
	parser.add_argument("--rav-data-dir", default="/home/user-data/rav", help="Path to rav data directory (default: /home/user-data/rav)")
	parser.add_argument("--users-db", default="/home/user-data/mail/db/users.sqlite", help="Path to the users SQLite database")
	parser.add_argument("--radicale-dir", default="/var/lib/radicale/collections", help="Path to Radicale multifilesystem collections directory")
	args = parser.parse_args()

	if os.path.exists(args.output):
		print(f"Output directory {args.output} already exists. Remove it or choose a different path.")
		sys.exit(1)

	os.makedirs(args.output)
	print(f"Exporting to {args.output} (storage={args.storage})\n")

	if args.storage == "rav":
		_export_rav(args.rav_data_dir, args.users_db, args.output)
	else:
		_export_files(args.radicale_dir, args.output)


if __name__ == "__main__":
	main()
