import sqlite3

from . import config

SCHEMA = """
create table if not exists source_state(
  source_id text primary key, status text, detail text,
  last_available_at text, last_scan_at text, files integer default 0);
create table if not exists copies(
  source_id text, relpath text, name text, size integer, mtime real,
  availability text, sha256 text, note text,
  first_seen_at text, last_seen_at text, gone integer default 0,
  primary key(source_id, relpath));
create index if not exists copies_sha on copies(sha256);
create index if not exists copies_name on copies(name);
create table if not exists copy_history(
  source_id text, relpath text, sha256 text, size integer, mtime real, observed_at text);
create table if not exists records(
  project text, key text, rev integer, kind text, body text,
  author text, source text, confidence text, created_at text,
  primary key(project, key, rev));
create table if not exists rejected_writes(
  id integer primary key, project text, key text, expected_rev integer, actual_rev integer,
  kind text, body text, author text, created_at text);
create table if not exists findings(
  id integer primary key, repo text, revision text, scanner text, rule text,
  severity text, confidence text, path text, line integer, evidence text, created_at text);
create table if not exists scans(
  id integer primary key, repo text, revision text, scanner text,
  status text, detail text, created_at text);
"""


def connect():
    con = sqlite3.connect(config.home() / "catalog.db", timeout=30)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    return con
