"""Source adapters: is the source really there, and is each file's content really local?

Dropbox and iCloud are read through their local synced folders on this Mac. That is
local-folder scope, not account-wide coverage. Nothing here downloads a placeholder:
classification uses lstat flags, names and extended attributes only.
"""
import ctypes
import ctypes.util
import os
import plistlib
import stat
import subprocess

from . import config

SF_DATALESS = 0x40000000  # APFS: metadata is local, content is in the cloud
EXCLUDE_DIRS = {".git", "node_modules", ".venv", "__pycache__", ".Trash", ".dropbox.cache", ".Spotlight-V100", ".fseventsd"}
EXCLUDE_FILES = {".DS_Store", ".dropbox", "Icon\r", ".localized"}

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
_libc.listxattr.restype = ctypes.c_ssize_t
_libc.listxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int]
XATTR_NOFOLLOW = 1


def xattr_names(path):
    b = os.fsencode(path)
    n = _libc.listxattr(b, None, 0, XATTR_NOFOLLOW)
    if n <= 0:
        return []
    buf = ctypes.create_string_buffer(n)
    n = _libc.listxattr(b, buf, n, XATTR_NOFOLLOW)
    return [x.decode(errors="replace") for x in buf.raw[: max(n, 0)].split(b"\0") if x]


def mount_point(path):
    p = os.path.realpath(path)
    while not os.path.ismount(p):
        p = os.path.dirname(p)
    return p


def volume_uuid(path):
    """Volume identity of the filesystem holding path, or None if it can't be read."""
    try:
        out = subprocess.run(["/usr/sbin/diskutil", "info", "-plist", mount_point(path)],
                             capture_output=True, timeout=20)
        return plistlib.loads(out.stdout).get("VolumeUUID")
    except Exception:
        return None


def source_state(src):
    """(status, detail). status: available | unavailable | remote."""
    if src.get("device") and src["device"] != config.device():
        return "remote", f"lives on device {src['device']}; this is {config.device()}"
    root = src["root"]
    if not os.path.isdir(root):
        return "unavailable", "root path is not present (offline, unmounted or not synced to this Mac)"
    if src["kind"] == "raid":
        found = volume_uuid(root)
        if found != src.get("volume_uuid"):
            return "unavailable", f"volume identity mismatch: expected {src.get('volume_uuid')}, found {found}"
    return "available", ""


def is_icloud_stub(name):
    return name.startswith(".") and name.endswith(".icloud") and len(name) > 8


def classify(path, st, kind):
    """readable | placeholder | symlink | special. 'readable' is confirmed only when hashed."""
    if stat.S_ISLNK(st.st_mode):
        return "symlink"
    if not stat.S_ISREG(st.st_mode):
        return "special"
    if getattr(st, "st_flags", 0) & SF_DATALESS:
        return "placeholder"
    if is_icloud_stub(os.path.basename(path)):
        return "placeholder"
    if kind == "dropbox":
        if any(x.startswith("com.dropbox.placeholder") for x in xattr_names(path)):
            return "placeholder"
        if st.st_size > 0 and st.st_blocks == 0 and not getattr(st, "st_flags", 0) & 0x20:
            return "placeholder"  # has a size but no local data (0x20 = compressed, which is local)
    return "readable"


def excluded(rel, excludes):
    rel = rel.rstrip("/")
    return any(rel == e.rstrip("/") or rel.startswith(e.rstrip("/") + "/") for e in excludes or [])


def walk(src):
    """Yield (relpath, abspath, size, mtime, availability). Never follows symlinks,
    never descends into cloud-only directories (listing them would fetch them)."""
    root, kind, excludes = src["root"], src["kind"], src.get("exclude")
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            entries = list(os.scandir(d))
        except OSError:
            continue
        for e in entries:
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            rel = os.path.relpath(e.path, root)
            if excluded(rel, excludes):
                continue
            if stat.S_ISDIR(st.st_mode):
                if e.name in EXCLUDE_DIRS:
                    continue
                if getattr(st, "st_flags", 0) & SF_DATALESS:
                    yield rel + "/", e.path, None, st.st_mtime, "placeholder_dir"
                    continue
                stack.append(e.path)
                continue
            if e.name in EXCLUDE_FILES:
                continue
            avail = classify(e.path, st, kind)
            if avail == "special":
                continue
            if is_icloud_stub(e.name):
                # Old-style iCloud stub ".name.icloud": the real file is "name", size unknown.
                rel = os.path.join(os.path.dirname(rel), e.name[1:-7])
                yield rel, e.path, None, st.st_mtime, avail
            else:
                yield rel, e.path, st.st_size, st.st_mtime, avail
