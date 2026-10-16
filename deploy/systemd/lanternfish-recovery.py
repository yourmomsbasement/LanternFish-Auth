#!/usr/bin/env python3
"""Optional encrypted backup and isolated restore-verification helper.

This is a standard-library-only helper for operators of a Lanternfish Gate
host. It wraps the external ``age`` binary (https://age-encryption.org) to
produce and read an encrypted archive of the small set of files a Gate needs
to recover: its data file, its Gate master key, and (optionally) its audit log.

Subcommands
-----------
``backup``   Stream a tar of the fixed, known files to ``age``'s stdin and the
             ciphertext straight to a newly created 0600 file. No plaintext is
             ever written to disk and no secret is written to stdout.
``verify``   Decrypt the archive in memory and check its structure, integrity
             manifest, JSON/key formats, size caps and (optionally) its age.
             It writes nothing.
``restore``  Run the same full validation, and only after it succeeds extract
             the files into a brand-new 0700 directory (files 0600).

Consistency: run these against a *stopped or otherwise stable* Gate snapshot.
``backup`` reads each file sequentially; a file being rewritten underneath it
is not a consistent snapshot. Stop ``lanternfish-gate`` first (see
``lanternfish-gatectl``), or copy the data files aside and point at the copies.

``age`` must be installed separately (e.g. ``apt install age`` or a release
binary on PATH); this helper never falls back to unencrypted output and never
implements its own cryptography.

Limitations: ``verify`` proves the archive's integrity, structure and formats.
It does *not* prove that the encrypted Gate data unseals with your master key;
only running the Gate can prove that.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as _dt
import errno
import hashlib
import io
import json
import math
import os
import signal
import stat as _stat
import subprocess
import sys
import tarfile
import threading

PROG = "lanternfish-recovery"
FORMAT_ID = "lanternfish-recovery/1"
MANIFEST_NAME = "manifest.json"
REQUIRED_ENTRIES = ("gate.json", "master_key")
OPTIONAL_ENTRIES = ("audit.log",)
DATA_ENTRIES = frozenset(REQUIRED_ENTRIES) | frozenset(OPTIONAL_ENTRIES)
ALLOWED_ENTRIES = DATA_ENTRIES | {MANIFEST_NAME}
DEFAULT_MAX_BYTES = 256 * 1024 * 1024
_CHUNK = 64 * 1024
_SUBPROCESS_TIMEOUT = 120

_EPILOG = """\
Consistency and setup:
  * Run against a stopped or otherwise stable Gate snapshot. backup reads the
    data file and master key one after another; a live rewrite is not atomic.
  * age must be installed separately and on PATH (or given with --age-binary).
    There is no plaintext fallback.

verification scope:
  verify checks that the archive is well formed, that entry names/types and the
  integrity manifest are intact, that the data file is JSON and the master key
  is a base64 32-byte value, and that size/age limits hold. It does not prove
  that the encrypted Gate data unseals with your master key.
"""


class RecoveryError(Exception):
    """A user-facing failure. Never carries secrets."""


class LimitError(RecoveryError):
    """A configured size or age limit was exceeded."""


class ValidationError(RecoveryError):
    """The archive failed structural or integrity validation."""


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def _utc_now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _iso(value: _dt.datetime) -> str:
    return value.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_utc(text: object) -> _dt.datetime:
    if not isinstance(text, str) or not text:
        raise ValidationError("manifest creation time is missing")
    trimmed = text.strip()
    if trimmed.endswith("Z"):
        trimmed = trimmed[:-1] + "+00:00"
    try:
        parsed = _dt.datetime.fromisoformat(trimmed)
    except ValueError as exc:
        raise ValidationError("manifest creation time is not a valid timestamp") from exc
    if parsed.tzinfo is None:
        raise ValidationError("manifest creation time is not timezone-aware")
    return parsed.astimezone(_dt.timezone.utc)


def _open_regular_nofollow(path: str):
    """Open a regular file read-only, refusing to follow a symlink."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise RecoveryError("refusing to read through a symlink") from exc
        raise RecoveryError("cannot open required file") from exc
    info = os.fstat(fd)
    if not _stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise RecoveryError("required input is not a regular file")
    return os.fdopen(fd, "rb"), info


def _decode_master_key(text: str) -> bytes:
    """Accept standard or URL-safe base64, padded or not, decoding to 32 bytes."""
    stripped = text.strip()
    unpadded = stripped.rstrip("=")
    if not unpadded:
        raise ValidationError("master key is empty")
    padding = "=" * (-len(unpadded) % 4)
    try:
        if "-" in unpadded or "_" in unpadded:
            raw = base64.b64decode(unpadded + padding, altchars=b"-_", validate=True)
        else:
            raw = base64.b64decode(unpadded + padding, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValidationError("master key is not valid base64") from exc
    if len(raw) != 32:
        raise ValidationError("master key must decode to 32 bytes")
    return raw


def _validate_gate_json(content: bytes) -> None:
    if not content:
        raise ValidationError("data file is empty")
    try:
        parsed = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("data file is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ValidationError("data file is not a JSON object")


def _validate_master_key_bytes(content: bytes) -> None:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError("master key is not valid UTF-8") from exc
    _decode_master_key(text)


def _positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if value <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return value


def _nonneg_float(text: str) -> float:
    try:
        value = float(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(value) or value < 0:
        raise argparse.ArgumentTypeError("must be a finite nonnegative number")
    return value


# --------------------------------------------------------------------------
# encryption/decryption plumbing
# --------------------------------------------------------------------------

def _kill_age(proc):
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except ProcessLookupError:
        pass


def _start_age(cmd, stdout, timeout=_SUBPROCESS_TIMEOUT):
    try:
        proc = subprocess.Popen(  # noqa: S603 - explicit argv, no shell
            cmd,
            stdin=subprocess.PIPE,
            stdout=stdout,
            stderr=subprocess.DEVNULL,
            start_new_session=(os.name == "posix"),
        )
        proc._lf_timed_out = threading.Event()
        def expire():
            # Kill the whole age/plugin group, including children that keep
            # a pipe open after the main age process has exited.
            proc._lf_timed_out.set()
            _kill_age(proc)
        proc._lf_watchdog = threading.Timer(timeout, expire)
        proc._lf_watchdog.daemon = True
        proc._lf_watchdog.start()
        return proc
    except FileNotFoundError as exc:
        raise RecoveryError(
            "external age binary not found; install age or pass --age-binary"
        ) from exc
    except OSError as exc:
        raise RecoveryError("could not start the external age binary") from exc


def _reap(proc: subprocess.Popen) -> int:
    try:
        status = proc.wait(timeout=_SUBPROCESS_TIMEOUT)
        proc._lf_watchdog.cancel()
        if proc._lf_timed_out.is_set():
            raise RecoveryError("external age operation timed out")
        return status
    except subprocess.TimeoutExpired:
        _kill_age(proc)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        raise RecoveryError("external age binary did not exit")


def _close_quietly(stream) -> None:
    try:
        if stream is not None:
            stream.close()
    except OSError:
        pass


def _feed_file_to_stdin(proc: subprocess.Popen, handle, errors: list) -> None:
    try:
        with handle:
            while True:
                chunk = handle.read(_CHUNK)
                if not chunk:
                    break
                proc.stdin.write(chunk)
        proc.stdin.flush()
    except (BrokenPipeError, OSError) as exc:
        errors.append(exc)
    finally:
        _close_quietly(proc.stdin)


# --------------------------------------------------------------------------
# archive construction
# --------------------------------------------------------------------------

class _HashingReader:
    """Read-through wrapper that hashes every byte and counts it."""

    def __init__(self, handle, hasher) -> None:
        self._handle = handle
        self._hasher = hasher
        self.count = 0

    def read(self, size: int = -1) -> bytes:
        chunk = self._handle.read(size)
        if chunk:
            self._hasher.update(chunk)
            self.count += len(chunk)
        return chunk

    def readable(self) -> bool:
        return True


def _tar_timestamp(info: os.stat_result) -> int:
    return int(info.st_mtime)


def _add_file(tar: tarfile.TarFile, name: str, path: str):
    handle, info = _open_regular_nofollow(path)
    with handle:
        tarinfo = tarfile.TarInfo(name=name)
        tarinfo.size = info.st_size
        tarinfo.mtime = _tar_timestamp(info)
        tarinfo.mode = 0o600
        tarinfo.type = tarfile.REGTYPE
        tarinfo.uid = 0
        tarinfo.gid = 0
        tarinfo.uname = ""
        tarinfo.gname = ""
        hasher = hashlib.sha256()
        reader = _HashingReader(handle, hasher)
        tar.addfile(tarinfo, reader)
        if reader.count != info.st_size:
            raise RecoveryError("input file changed while being archived")
        return {"sha256": hasher.hexdigest(), "size": info.st_size}


def _add_bytes(tar: tarfile.TarFile, name: str, blob: bytes, mtime: int) -> None:
    tarinfo = tarfile.TarInfo(name=name)
    tarinfo.size = len(blob)
    tarinfo.mtime = mtime
    tarinfo.mode = 0o600
    tarinfo.type = tarfile.REGTYPE
    tarinfo.uid = 0
    tarinfo.gid = 0
    tarinfo.uname = ""
    tarinfo.gname = ""
    tar.addfile(tarinfo, io.BytesIO(blob))


def _write_archive(dest, data_path, key_path, audit_path, max_bytes: int) -> None:
    """Write the tar stream (manifest last) to ``dest`` (age's stdin)."""
    created = _utc_now()
    created_iso = _iso(created)
    created_epoch = int(created.timestamp())

    files = [("gate.json", data_path), ("master_key", key_path)]
    if audit_path is not None:
        files.append(("audit.log", audit_path))

    with tarfile.open(fileobj=dest, mode="w|", format=tarfile.GNU_FORMAT) as tar:
        entries = {}
        total = 0
        for name, path in files:
            handle, info = _open_regular_nofollow(path)
            handle.close()
            if info.st_size < 0:
                raise RecoveryError("refusing to archive a file with a negative size")
            total += info.st_size
            if total > max_bytes:
                raise LimitError("input files exceed the --max-bytes cap")
            entries[name] = _add_file(tar, name, path)
        manifest = {
            "format": FORMAT_ID,
            "created": created_iso,
            "entries": entries,
        }
        blob = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        _add_bytes(tar, MANIFEST_NAME, blob, created_epoch)


# --------------------------------------------------------------------------
# archive reading and validation
# --------------------------------------------------------------------------

class _LimitExceeded(Exception):
    pass


class _LimitedReader:
    """Read-through wrapper that refuses to read past a byte cap."""

    def __init__(self, handle, limit: int) -> None:
        self._handle = handle
        self._limit = limit
        self.total = 0
        self.tail = bytearray()

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = _CHUNK
        size = min(size, _CHUNK, self._limit - self.total + 1)
        chunk = self._handle.read(size)
        if chunk:
            self.total += len(chunk)
            self.tail += chunk
            if len(self.tail) > _CHUNK:
                del self.tail[:-_CHUNK]
            if self.total > self._limit:
                raise _LimitExceeded
        return chunk

    def readable(self) -> bool:
        return True


def _check_entry_name(name: object) -> str:
    if not isinstance(name, str) or name == "":
        raise ValidationError("refusing archive entry with an empty name")
    if "\x00" in name:
        raise ValidationError("refusing archive entry name containing NUL")
    if name != os.path.basename(name) or name in (".", "..") or "/" in name or "\\" in name:
        raise ValidationError("refusing unsafe (traversal) archive entry name")
    if name not in ALLOWED_ENTRIES:
        raise ValidationError("refusing unexpected archive entry name")
    return name


def _read_and_validate(limited, max_bytes: int, max_age_hours):
    """Return {"entries": {name: {...}}, "created": datetime}. Reads only."""
    try:
        tar = tarfile.open(fileobj=limited, mode="r|")
    except tarfile.TarError as exc:
        raise ValidationError("archive is not a readable tar stream") from exc

    found = {}
    declared_total = 0
    with tar:
        while True:
            try:
                member = tar.next()
            except tarfile.TarError as exc:
                raise ValidationError("archive tar stream is truncated or corrupt") from exc
            if member is None:
                break
            name = _check_entry_name(member.name)
            if name in found:
                raise ValidationError("refusing duplicate archive entry name")
            if not (member.isreg() and member.type in (tarfile.REGTYPE, tarfile.AREGTYPE)):
                raise ValidationError("refusing non-regular archive entry (link or special file)")
            if member.size < 0:
                raise ValidationError("refusing archive entry with a negative size")
            declared_total += member.size
            if declared_total > max_bytes:
                raise LimitError("archive entries exceed the --max-bytes cap")
            try:
                source = tar.extractfile(member)
            except tarfile.TarError as exc:
                raise ValidationError("archive entry is unreadable") from exc
            if source is None:
                raise ValidationError("archive entry is unreadable")
            hasher = hashlib.sha256()
            size = 0
            chunks = bytearray()
            while True:
                try:
                    chunk = source.read(_CHUNK)
                except _LimitExceeded:
                    raise LimitError("archive exceeds the --max-bytes cap")
                except tarfile.TarError as exc:
                    raise ValidationError("archive tar stream is truncated or corrupt") from exc
                if not chunk:
                    break
                hasher.update(chunk)
                size += len(chunk)
                chunks += chunk
            if size != member.size:
                raise ValidationError("archive entry is shorter than declared")
            found[name] = {
                "sha256": hasher.hexdigest(),
                "size": size,
                "content": bytes(chunks),
            }

    archive_end = tar.offset
    data_names = set(found) - {MANIFEST_NAME}
    if set(found) - {MANIFEST_NAME} - DATA_ENTRIES:
        raise ValidationError("refusing unexpected archive entry name")
    if set(REQUIRED_ENTRIES) - data_names:
        raise ValidationError("archive is missing a required entry")
    if MANIFEST_NAME not in found:
        raise ValidationError("archive integrity manifest is missing")

    manifest = _parse_manifest(found[MANIFEST_NAME]["content"])
    entries = manifest["entries"]
    if set(entries) != data_names:
        raise ValidationError("integrity manifest does not match the archive entries")
    for name, meta in entries.items():
        actual = found[name]
        if meta["size"] != actual["size"]:
            raise ValidationError("integrity manifest size does not match an entry")
        if meta["sha256"] != actual["sha256"]:
            raise ValidationError("integrity manifest digest does not match an entry")

    _validate_gate_json(found["gate.json"]["content"])
    _validate_master_key_bytes(found["master_key"]["content"])

    created = _parse_utc(manifest["created"])
    if created > _utc_now() + _dt.timedelta(minutes=5):
        raise ValidationError("manifest creation time is in the future")
    if max_age_hours is not None:
        age_seconds = (_utc_now() - created).total_seconds()
        if age_seconds > max_age_hours * 3600:
            raise LimitError("archive is older than the allowed --max-age")

    return {"entries": found, "created": created, "manifest": manifest, "archive_end": archive_end}


def _parse_manifest(content: bytes) -> dict:
    try:
        manifest = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("integrity manifest is not valid JSON") from exc
    if not isinstance(manifest, dict):
        raise ValidationError("integrity manifest is not a JSON object")
    if manifest.get("format") != FORMAT_ID:
        raise ValidationError("unrecognized integrity manifest format")
    if not isinstance(manifest.get("created"), str):
        raise ValidationError("integrity manifest is missing a creation time")
    entries = manifest.get("entries")
    if not isinstance(entries, dict):
        raise ValidationError("integrity manifest entries are malformed")
    for name, meta in entries.items():
        if name not in DATA_ENTRIES:
            raise ValidationError("integrity manifest lists an unexpected entry")
        if not isinstance(meta, dict):
            raise ValidationError("integrity manifest entry is malformed")
        digest = meta.get("sha256")
        size = meta.get("size")
        if not isinstance(digest, str) or len(digest) != 64 or any(
            ch not in "0123456789abcdef" for ch in digest
        ):
            raise ValidationError("integrity manifest holds an invalid digest")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValidationError("integrity manifest holds an invalid size")
    return manifest


def _decrypt_validated(archive_path, identity, age_binary, max_bytes, max_age_hours, timeout=_SUBPROCESS_TIMEOUT):
    """Decrypt ``archive_path`` and validate it in memory. Writes nothing."""
    archive, info = _open_regular_nofollow(archive_path)
    if info.st_size > max_bytes * 2 + 65536:
        archive.close()
        raise LimitError("encrypted archive exceeds the input size cap")
    cmd = [age_binary, "--decrypt", "-i", identity]
    try:
        proc = _start_age(cmd, subprocess.PIPE, timeout)
    except Exception:
        archive.close()
        raise
    limited = _LimitedReader(proc.stdout, max_bytes)
    errors: list = []
    feeder = threading.Thread(
        target=_feed_file_to_stdin, args=(proc, archive, errors), daemon=True
    )
    feeder.start()

    result = None
    failure = None
    try:
        result = _read_and_validate(limited, max_bytes, max_age_hours)
        # tarfile may prefetch beyond its logical end. Inspect that buffered
        # tail as well as later reads: only zero record padding may follow.
        relative = result["archive_end"] - (limited.total - len(limited.tail))
        if relative < 0 or relative > len(limited.tail) or any(limited.tail[relative:]):
            raise ValidationError("nonzero or truncated data after tar archive")
        while True:
            trailing = limited.read(_CHUNK)
            if not trailing:
                break
            if any(trailing):
                raise ValidationError("nonzero data after tar archive")
    except _LimitExceeded:
        failure = LimitError("archive exceeds the --max-bytes cap")
    except (ValidationError, LimitError) as exc:
        failure = exc
    except tarfile.TarError as exc:  # pragma: no cover - defensive
        failure = ValidationError("archive tar stream is truncated or corrupt")
    except Exception:  # pragma: no cover - defensive
        failure = ValidationError("archive could not be read")

    produced = limited.total
    if failure is not None and proc.poll() is None:
        # Stop age so a full pipe cannot block the feeder thread.
        _kill_age(proc)
    _close_quietly(proc.stdout)

    feeder.join(timeout=_SUBPROCESS_TIMEOUT)
    if feeder.is_alive():
        if proc.poll() is None:
            _kill_age(proc)
        feeder.join(timeout=10)
        raise RecoveryError("timed out reading the encrypted archive")

    returncode = _reap(proc)
    if failure is not None:
        # If age produced no usable output, its exit status explains the failure.
        if produced == 0 and returncode != 0:
            raise RecoveryError("decryption failed (age exit status %d)" % returncode)
        raise failure
    if returncode != 0:
        raise RecoveryError("decryption failed (age exit status %d)" % returncode)
    if errors:
        raise RecoveryError("could not read the encrypted archive completely")
    return result


# --------------------------------------------------------------------------
# subcommands
# --------------------------------------------------------------------------

def cmd_backup(args) -> int:
    if not args.recipient:
        raise RecoveryError("backup needs at least one --recipient")
    if os.path.exists(args.output):
        raise RecoveryError("output already exists; refusing to overwrite it")

    # Validate the master key up front (fail closed before creating output).
    key_handle, key_info = _open_regular_nofollow(args.master_key)
    with key_handle:
        if key_info.st_size > 4096:
            raise LimitError("master key file is too large")
        _validate_master_key_bytes(key_handle.read(4096))

    inputs = [args.data, args.master_key]
    if args.include_audit is not None:
        inputs.append(args.include_audit)
    total = 0
    for path in inputs:
        handle, info = _open_regular_nofollow(path)
        handle.close()
        total += info.st_size
    if total > args.max_bytes:
        raise LimitError("input files exceed the --max-bytes cap")

    with _open_regular_nofollow(args.data)[0] as handle:
        _validate_gate_json(handle.read(args.max_bytes + 1))
    try:
        out_fd = os.open(
            args.output,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
    except FileExistsError as exc:
        raise RecoveryError("output already exists; refusing to overwrite it") from exc
    except OSError as exc:
        raise RecoveryError("cannot create the output file") from exc

    cmd = [args.age_binary, "--encrypt"]
    for recipient in args.recipient:
        cmd += ["-r", recipient]

    proc = None
    success = False
    try:
        proc = _start_age(cmd, out_fd, args.timeout)
        try:
            _write_archive(
                proc.stdin, args.data, args.master_key, args.include_audit, args.max_bytes
            )
        except BrokenPipeError as exc:
            raise RecoveryError("encryption interrupted before archive completion") from exc
        finally:
            _close_quietly(proc.stdin)
        returncode = _reap(proc)
        if returncode != 0:
            raise RecoveryError("encryption failed (age exit status %d)" % returncode)
        success = True
    finally:
        if not success and proc is not None and proc.poll() is None:
            _kill_age(proc)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover - defensive
                pass
        output_identity = os.fstat(out_fd)
        os.close(out_fd)
        if proc is not None:
            proc._lf_watchdog.cancel()
        if not success:
            # Delete only the partial output we created; never touch anything else.
            try:
                current = os.lstat(args.output)
                if (current.st_dev, current.st_ino) == (output_identity.st_dev, output_identity.st_ino):
                    os.unlink(args.output)
            except OSError:
                pass

    print("backed up archive written to the requested output (mode 0600)")
    return 0


def cmd_verify(args) -> int:
    result = _decrypt_validated(
        args.archive, args.identity, args.age_binary, args.max_bytes, args.max_age, args.timeout
    )
    entries = result["entries"]
    data_names = sorted(set(entries) - {MANIFEST_NAME})
    total = sum(entries[name]["size"] for name in data_names)
    print("archive verified: %d entr%s, %d byte(s), created %s"
          % (len(data_names), "y" if len(data_names) == 1 else "ies", total,
             _iso(result["created"])))
    print("verify checks archive integrity and formats only; it does not prove the")
    print("encrypted Gate data unseals with your master key.")
    return 0


def cmd_restore(args) -> int:
    if os.path.exists(args.destination):
        raise RecoveryError("destination already exists; refusing to overwrite it")

    result = _decrypt_validated(
        args.archive, args.identity, args.age_binary, args.max_bytes, args.max_age, args.timeout
    )
    entries = result["entries"]

    # Resolve a private, caller-owned parent once, then use directory-relative
    # descriptors. A path replacement cannot redirect chmod/writes/cleanup.
    parent_path, basename = os.path.split(os.path.abspath(args.destination))
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        parent_fd = os.open(parent_path, flags)
    except OSError as exc:
        raise RecoveryError("cannot open a safe restore parent directory") from exc
    directory_fd = None
    written = []
    created = False
    identity = None
    try:
        parent_info = os.fstat(parent_fd)
        if parent_info.st_uid != os.geteuid() or parent_info.st_mode & 0o022:
            raise RecoveryError("restore parent must be caller-owned and not group/world-writable")
        try:
            os.mkdir(basename, 0o700, dir_fd=parent_fd)
        except FileExistsError as exc:
            raise RecoveryError("destination already exists; refusing to overwrite it") from exc
        created = True
        directory_fd = os.open(basename, flags, dir_fd=parent_fd)
        identity = os.fstat(directory_fd)
        if identity.st_uid != os.geteuid() or not _stat.S_ISDIR(identity.st_mode):
            raise RecoveryError("restore destination identity changed")
        os.fchmod(directory_fd, 0o700)
        for name in ("gate.json", "master_key", "audit.log"):
            if name not in entries:
                continue
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                         0o600, dir_fd=directory_fd)
            written.append(name)
            try:
                os.fchmod(fd, 0o600)
                _write_all(fd, entries[name]["content"])
            finally:
                os.close(fd)
    except (OSError, RecoveryError) as exc:
        if directory_fd is not None:
            for name in written:
                try:
                    os.unlink(name, dir_fd=directory_fd)
                except OSError:
                    pass
        if created and identity is not None:
            try:
                current = os.stat(basename, dir_fd=parent_fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                    os.rmdir(basename, dir_fd=parent_fd)
            except OSError:
                pass
        if isinstance(exc, RecoveryError):
            raise
        raise RecoveryError("failed to write the restore destination") from exc
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
        os.close(parent_fd)

    print("restored %d file(s) to the requested destination (mode 0700/0600)" % len(written))
    return 0


def _write_all(fd: int, blob: bytes) -> None:
    view = memoryview(blob)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _add_common(parser) -> None:
    parser.add_argument("--timeout", type=_positive_int, default=_SUBPROCESS_TIMEOUT,
                        help="maximum age process duration in seconds (default 120)")
    parser.add_argument(
        "--age-binary",
        default="age",
        help="external age executable to run (default: age from PATH)",
    )
    parser.add_argument(
        "--max-bytes",
        type=_positive_int,
        default=DEFAULT_MAX_BYTES,
        help="cap on decrypted/archive bytes, default 268435456 (256 MiB)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "Optional encrypted backup and isolated restore verification for a "
            "Lanternfish Gate host, using the external age binary."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    backup = sub.add_parser(
        "backup",
        help="encrypt an archive of gate.json, the master key and optional audit log",
        description="Stream a tar archive to age and its ciphertext to a new 0600 file.",
    )
    backup.add_argument("--data", required=True, help="path to gate.json")
    backup.add_argument("--master-key", dest="master_key", required=True,
                        help="path to the base64 32-byte Gate master key file")
    backup.add_argument("--include-audit", dest="include_audit", default=None,
                        help="optional path to audit.log to include")
    backup.add_argument("--recipient", "-r", action="append", default=[], required=True,
                        help="age recipient (repeatable; at least one required)")
    backup.add_argument("--output", required=True, help="new file to write ciphertext to")
    _add_common(backup)
    backup.set_defaults(func=cmd_backup)

    verify = sub.add_parser(
        "verify",
        help="decrypt and validate an archive without writing anything",
        description="Decrypt an archive in memory and check its integrity and formats.",
    )
    verify.add_argument("archive", help="encrypted archive to verify")
    verify.add_argument("--identity", "-i", required=True,
                        help="age identity (private key) file to decrypt with")
    verify.add_argument("--max-age", dest="max_age", type=_nonneg_float, default=None,
                        help="refuse archives older than this many hours")
    _add_common(verify)
    verify.set_defaults(func=cmd_verify)

    restore = sub.add_parser(
        "restore",
        help="validate an archive, then extract it to a brand-new directory",
        description="Validate fully, then restore into a new 0700 directory (files 0600).",
    )
    restore.add_argument("archive", help="encrypted archive to restore")
    restore.add_argument("--identity", "-i", required=True,
                         help="age identity (private key) file to decrypt with")
    restore.add_argument("--destination", required=True,
                         help="new directory to write the recovered files into")
    restore.add_argument("--max-age", dest="max_age", type=_nonneg_float, default=None,
                         help="refuse archives older than this many hours")
    _add_common(restore)
    restore.set_defaults(func=cmd_restore)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except RecoveryError as exc:
        print("%s: error: %s" % (PROG, exc), file=sys.stderr)
        return 1
    except BrokenPipeError:
        return 1
    except KeyboardInterrupt:
        print("%s: interrupted" % PROG, file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
