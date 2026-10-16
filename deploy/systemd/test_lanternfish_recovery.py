#!/usr/bin/env python3
"""Tests for lanternfish-recovery.

The tests use a fake ``age`` executable to exercise the process plumbing
(argument handling, streaming, exit-status checks). The fake is deliberately
*not* cryptography -- it is a reversible obfuscation with a tag so we can
simulate a wrong identity. A real age round trip runs only if ``age`` and
``age-keygen`` are installed.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "lanternfish-recovery.py"

FAKE_AGE_SRC = r'''#!/usr/bin/env python3
# Fake age for tests. NOT cryptography: reversible XOR with a key derived from
# the recipient string (encrypt) or the identity file contents (decrypt).
import hashlib
import sys


def keystream(key, n):
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(key + str(counter).encode()).digest()
        counter += 1
    return bytes(out[:n])


def xor(data, key):
    return bytes(b ^ k for b, k in zip(data, key))


def main():
    args = sys.argv[1:]
    mode = None
    source = None
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--encrypt":
            mode = "enc"
        elif arg == "--decrypt":
            mode = "dec"
        elif arg in ("-r", "--recipient"):
            source = args[i + 1]
            i += 1
        elif arg in ("-i", "--identity"):
            try:
                with open(args[i + 1], "r") as handle:
                    source = handle.read().strip()
            except OSError:
                return 1
            i += 1
        i += 1
    data = sys.stdin.buffer.read()
    if mode is None or source is None:
        sys.stderr.write("fake age: bad usage\n")
        return 2
    key = hashlib.sha256(source.encode()).digest()
    tag = hashlib.sha256(key).digest()[:8]
    header = b"FAKEAGE1" + tag
    if mode == "enc":
        sys.stdout.buffer.write(header + xor(data, keystream(key, len(data))))
        return 0
    if len(data) < 16 or data[:8] != b"FAKEAGE1" or data[8:16] != tag:
        sys.stderr.write("fake age: cannot decrypt\n")
        return 1
    sys.stdout.buffer.write(xor(data[16:], keystream(key, len(data) - 16)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def _age_installed() -> bool:
    return bool(shutil.which("age")) and bool(shutil.which("age-keygen"))


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class RecoveryHelpers(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="lfr-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

        self.fake_age = self.tmp / "fake-age"
        self.fake_age.write_text(FAKE_AGE_SRC)
        self.fake_age.chmod(0o755)

        self.recipient = "test-recipient"
        self.identity = self.tmp / "identity.txt"
        self.identity.write_text(self.recipient + "\n")

        self.data = self.tmp / "gate.json"
        self.key = self.tmp / "master_key"
        self.audit = self.tmp / "audit.log"

        self.data_bytes = json.dumps({"version": 1, "devices": []}).encode("utf-8")
        self.key_bytes = base64.b64encode(os.urandom(32))
        self.audit_bytes = b'{"event":"enroll"}\n'
        self.data.write_bytes(self.data_bytes)
        self.key.write_bytes(self.key_bytes)
        self.audit.write_bytes(self.audit_bytes)

    # -- helpers -----------------------------------------------------------

    def run_cli(self, *args, age=True) -> subprocess.CompletedProcess:
        cmd = [sys.executable, str(SCRIPT)]
        cmd += list(args)
        return subprocess.run(
            cmd, capture_output=True, text=True, cwd=str(self.tmp), timeout=20
        )

    def backup(self, output, *, audit=None, recipients=None, extra=(), expect=0):
        recipients = [self.recipient] if recipients is None else recipients
        args = ["backup", "--age-binary", str(self.fake_age),
                "--data", str(self.data), "--master-key", str(self.key),
                "--output", str(output)]
        if audit is not None:
            args += ["--include-audit", str(audit)]
        for recipient in recipients:
            args += ["-r", recipient]
        args += list(extra)
        proc = self.run_cli(*args)
        if expect is not None:
            self.assertEqual(proc.returncode, expect, proc.stderr)
        return proc

    def verify(self, archive, *, identity=None, extra=(), expect=0):
        identity = identity or self.identity
        args = ["verify", "--age-binary", str(self.fake_age),
                "--identity", str(identity), str(archive)]
        args += list(extra)
        proc = self.run_cli(*args)
        if expect is not None:
            self.assertEqual(proc.returncode, expect, proc.stderr)
        return proc

    def restore(self, archive, destination, *, identity=None, extra=(), expect=0):
        identity = identity or self.identity
        args = ["restore", "--age-binary", str(self.fake_age),
                "--identity", str(identity), "--destination", str(destination),
                str(archive)]
        args += list(extra)
        proc = self.run_cli(*args)
        if expect is not None:
            self.assertEqual(proc.returncode, expect, proc.stderr)
        return proc

    def make_manifest(self, entries, created=None):
        created = created or datetime.datetime.now(
            datetime.timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        return {
            "format": "lanternfish-recovery/1",
            "created": created,
            "entries": {
                name: {"sha256": _sha256_hex(content), "size": len(content)}
                for name, content in entries.items()
            },
        }

    def regular_member(self, name, content):
        info = tarfile.TarInfo(name=name)
        info.size = len(content)
        info.type = tarfile.REGTYPE
        info.mode = 0o600
        return info, content

    def write_tar(self, members, path):
        with tarfile.open(path, "w") as tar:
            for info, content in members:
                tar.addfile(info, io.BytesIO(content) if content is not None else None)
        return path

    def encrypt(self, plain: Path, out: Path, recipient=None):
        recipient = recipient or self.recipient
        with open(plain, "rb") as fin, open(out, "wb") as fout:
            proc = subprocess.run(
                [str(self.fake_age), "--encrypt", "-r", recipient],
                stdin=fin, stdout=fout,
            )
        self.assertEqual(proc.returncode, 0)
        return out

    def craft_archive(self, members, *, recipient=None, name="archive.age"):
        plain = self.tmp / (name + ".plain")
        self.write_tar(members, plain)
        return self.encrypt(plain, self.tmp / name, recipient=recipient)

    def standard_archive(self, *, entries=None, audit=None, created=None,
                         tamper=None, recipient=None):
        entries = dict(entries or {
            "gate.json": self.data_bytes,
            "master_key": self.key_bytes,
        })
        if audit:
            entries["audit.log"] = audit
        manifest = self.make_manifest(entries, created=created)
        if tamper is not None:
            name, digest = tamper
            manifest["entries"][name]["sha256"] = digest
        members = [self.regular_member(n, c) for n, c in entries.items()]
        manifest_bytes = json.dumps(manifest).encode("utf-8")
        members.append(self.regular_member("manifest.json", manifest_bytes))
        return self.craft_archive(members, recipient=recipient)

    # -- tests -------------------------------------------------------------

class RecoveryTestBase(RecoveryHelpers):

    def test_backup_verify_restore_roundtrip(self):
        archive = self.tmp / "backup.age"
        self.backup(archive, audit=self.audit)
        self.assertTrue(archive.exists())
        self.assertEqual(archive.stat().st_mode & 0o777, 0o600)

        proc = self.verify(archive)
        self.assertIn("archive verified", proc.stdout)

        dest = self.tmp / "restored"
        proc = self.restore(archive, dest)
        self.assertEqual(dest.stat().st_mode & 0o777, 0o700)
        for name, expected in (
            ("gate.json", self.data_bytes),
            ("master_key", self.key_bytes),
            ("audit.log", self.audit_bytes),
        ):
            path = dest / name
            self.assertTrue(path.is_file(), name)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600, name)
            self.assertEqual(path.read_bytes(), expected, name)

    def test_backup_without_audit(self):
        archive = self.tmp / "backup.age"
        self.backup(archive)
        dest = self.tmp / "restored"
        self.restore(archive, dest)
        self.assertTrue((dest / "gate.json").is_file())
        self.assertTrue((dest / "master_key").is_file())
        self.assertFalse((dest / "audit.log").exists())

    def test_backup_output_not_overwritten(self):
        archive = self.tmp / "backup.age"
        self.backup(archive)
        original = archive.read_bytes()
        proc = self.backup(archive, expect=1)
        self.assertIn("refusing to overwrite", proc.stderr)
        self.assertEqual(archive.read_bytes(), original)

    def test_restore_destination_not_overwritten(self):
        archive = self.tmp / "backup.age"
        self.backup(archive)
        dest = self.tmp / "restored"
        self.restore(archive, dest)
        sentinel = dest / "gate.json"
        before = sentinel.read_bytes()
        proc = self.restore(archive, dest, expect=1)
        self.assertIn("refusing to overwrite", proc.stderr)
        self.assertEqual(sentinel.read_bytes(), before)

    def test_digest_mismatch_fails(self):
        archive = self.standard_archive(tamper=("gate.json", "0" * 64))
        proc = self.verify(archive, expect=1)
        self.assertIn("digest", proc.stderr)

    def test_size_mismatch_fails(self):
        entries = {"gate.json": self.data_bytes, "master_key": self.key_bytes}
        manifest = self.make_manifest(entries)
        manifest["entries"]["master_key"]["size"] = 999999
        members = [self.regular_member(n, c) for n, c in entries.items()]
        members.append(self.regular_member("manifest.json", json.dumps(manifest).encode()))
        archive = self.craft_archive(members)
        proc = self.verify(archive, expect=1)
        self.assertIn("size", proc.stderr)

    def test_corrupt_ciphertext_fails(self):
        archive = self.tmp / "backup.age"
        self.backup(archive)
        blob = bytearray(archive.read_bytes())
        blob[0] ^= 0xFF
        archive.write_bytes(bytes(blob))
        proc = self.verify(archive, expect=1)
        self.assertIn("decryption failed", proc.stderr)

    def test_wrong_identity_fails(self):
        wrong = self.tmp / "wrong.txt"
        wrong.write_text("someone-else\n")
        archive = self.tmp / "backup.age"
        self.backup(archive)
        proc = self.verify(archive, identity=wrong, expect=1)
        self.assertIn("decryption failed", proc.stderr)

    def test_missing_age_fails_closed(self):
        archive = self.tmp / "backup.age"
        args = ["backup", "--age-binary", str(self.tmp / "does-not-exist"),
                "--data", str(self.data), "--master-key", str(self.key),
                "--output", str(archive), "-r", self.recipient]
        proc = self.run_cli(*args)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertFalse(archive.exists())

        self.backup(archive)
        proc = self.run_cli("verify", "--age-binary", str(self.tmp / "nope"),
                            "--identity", str(self.identity), str(archive))
        self.assertEqual(proc.returncode, 1, proc.stderr)

    def test_missing_archive_fails_closed(self):
        proc = self.verify(self.tmp / "does-not-exist.age", expect=1)
        self.assertIn("cannot open", proc.stderr)

    def test_backup_requires_recipient(self):
        archive = self.tmp / "backup.age"
        proc = self.run_cli("backup", "--age-binary", str(self.fake_age),
                            "--data", str(self.data), "--master-key", str(self.key),
                            "--output", str(archive))
        self.assertEqual(proc.returncode, 2, proc.stderr)

    def test_backup_rejects_bad_master_key(self):
        self.key.write_text("not-base64!!")
        archive = self.tmp / "backup.age"
        proc = self.backup(archive, expect=1)
        self.assertIn("master key", proc.stderr)
        self.assertFalse(archive.exists())

    def test_verify_rejects_bad_key_format(self):
        archive = self.standard_archive(entries={
            "gate.json": self.data_bytes,
            "master_key": b"short",
        })
        proc = self.verify(archive, expect=1)
        self.assertIn("master key", proc.stderr)

    def test_verify_rejects_invalid_json(self):
        archive = self.standard_archive(entries={
            "gate.json": b"{not json",
            "master_key": self.key_bytes,
        })
        proc = self.verify(archive, expect=1)
        self.assertIn("JSON", proc.stderr)

    def test_traversal_name_refused(self):
        entries = {"gate.json": self.data_bytes, "master_key": self.key_bytes}
        manifest = self.make_manifest({**entries, "../evil": b"x"})
        members = [self.regular_member(n, c) for n, c in entries.items()]
        members.append(self.regular_member("../evil", b"x"))
        members.append(self.regular_member("manifest.json", json.dumps(manifest).encode()))
        archive = self.craft_archive(members)
        proc = self.verify(archive, expect=1)
        self.assertIn("unsafe", proc.stderr)

    def test_symlink_refused(self):
        entries = {"gate.json": self.data_bytes, "master_key": self.key_bytes}
        manifest = self.make_manifest(entries)
        members = [self.regular_member(n, c) for n, c in entries.items()]
        link = tarfile.TarInfo(name="audit.log")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        members.append((link, None))
        members.append(self.regular_member("manifest.json", json.dumps(manifest).encode()))
        archive = self.craft_archive(members)
        proc = self.verify(archive, expect=1)
        self.assertIn("non-regular", proc.stderr)

    def test_hardlink_refused(self):
        entries = {"gate.json": self.data_bytes, "master_key": self.key_bytes}
        manifest = self.make_manifest(entries)
        members = [self.regular_member(n, c) for n, c in entries.items()]
        link = tarfile.TarInfo(name="audit.log")
        link.type = tarfile.LNKTYPE
        link.linkname = "gate.json"
        members.append((link, None))
        members.append(self.regular_member("manifest.json", json.dumps(manifest).encode()))
        archive = self.craft_archive(members)
        proc = self.verify(archive, expect=1)
        self.assertIn("non-regular", proc.stderr)

    def test_duplicate_name_refused(self):
        entries = {"gate.json": self.data_bytes, "master_key": self.key_bytes}
        manifest = self.make_manifest(entries)
        members = [self.regular_member(n, c) for n, c in entries.items()]
        members.append(self.regular_member("gate.json", self.data_bytes))
        members.append(self.regular_member("manifest.json", json.dumps(manifest).encode()))
        archive = self.craft_archive(members)
        proc = self.verify(archive, expect=1)
        self.assertIn("duplicate", proc.stderr)

    def test_unexpected_name_refused(self):
        entries = {"gate.json": self.data_bytes, "master_key": self.key_bytes}
        manifest = self.make_manifest({**entries, "evil.txt": b"x"})
        members = [self.regular_member(n, c) for n, c in entries.items()]
        members.append(self.regular_member("evil.txt", b"x"))
        members.append(self.regular_member("manifest.json", json.dumps(manifest).encode()))
        archive = self.craft_archive(members)
        proc = self.verify(archive, expect=1)
        self.assertIn("unexpected", proc.stderr)

    def test_oversize_archive_refused(self):
        big = b"x" * 4096
        archive = self.standard_archive(entries={
            "gate.json": big,
            "master_key": self.key_bytes,
        })
        proc = self.verify(archive, extra=["--max-bytes", "256"], expect=1)
        self.assertIn("max-bytes", proc.stderr)

    def test_expiration(self):
        old = (datetime.datetime.now(datetime.timezone.utc)
               - datetime.timedelta(hours=100))
        archive = self.standard_archive(
            created=old.strftime("%Y-%m-%dT%H:%M:%SZ"))
        proc = self.verify(archive, extra=["--max-age", "1"], expect=1)
        self.assertIn("max-age", proc.stderr)
        self.verify(archive, extra=["--max-age", "1000"])

    def test_verify_writes_nothing(self):
        archive = self.tmp / "backup.age"
        self.backup(archive)
        before = sorted(p.name for p in self.tmp.iterdir())
        self.verify(archive)
        after = sorted(p.name for p in self.tmp.iterdir())
        self.assertEqual(before, after)

    def test_backup_refuses_symlinked_input(self):
        link = self.tmp / "gate-link.json"
        os.symlink(self.data, link)
        archive = self.tmp / "backup.age"
        args = ["backup", "--age-binary", str(self.fake_age),
                "--data", str(link), "--master-key", str(self.key),
                "--output", str(archive), "-r", self.recipient]
        proc = self.run_cli(*args)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn("symlink", proc.stderr)
        self.assertFalse(archive.exists())

    def test_help(self):
        proc = self.run_cli("--help")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("age", proc.stdout.lower())
        self.assertIn("stopped", proc.stdout.lower())

    def test_no_secrets_in_output(self):
        archive = self.tmp / "backup.age"
        self.backup(archive, audit=self.audit)
        proc = self.verify(archive)
        secret = self.key_bytes.decode()
        for text in (proc.stdout, proc.stderr):
            self.assertNotIn(secret, text)
            self.assertNotIn(self.recipient, text)
            self.assertNotIn(str(self.identity), text)


    def test_external_age_timeout_fails_closed(self):
        hanging = self.tmp / "hanging-age"
        hanging.write_text("#!/usr/bin/env python3\nimport time\ntime.sleep(60)\n")
        hanging.chmod(0o755)
        output = self.tmp / "timeout.age"
        proc = self.run_cli("backup", "--age-binary", str(hanging), "--timeout", "1",
                            "--data", str(self.data), "--master-key", str(self.key),
                            "--output", str(output), "-r", self.recipient)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertFalse(output.exists())
        self.backup(output)
        proc = self.run_cli("verify", "--age-binary", str(hanging), "--timeout", "1",
                            "--identity", str(self.identity), str(output))
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn("timed out", proc.stderr)

    @unittest.skipUnless(os.name == "posix", "POSIX process groups")
    def test_age_child_cannot_hold_pipe_past_timeout(self):
        child_age = self.tmp / "child-age"
        child_age.write_text("#!/usr/bin/env python3\nimport subprocess,sys\nsubprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])\n")
        child_age.chmod(0o755)
        output = self.tmp / "child.age"
        self.backup(output)
        proc = self.run_cli("verify", "--age-binary", str(child_age), "--timeout", "1",
                            "--identity", str(self.identity), str(output))
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn("timed out", proc.stderr)

    def test_restore_refuses_writable_parent(self):
        output = self.tmp / "parent.age"
        self.backup(output)
        unsafe = self.tmp / "shared"
        unsafe.mkdir(mode=0o777)
        unsafe.chmod(0o777)
        dest = unsafe / "restore"
        proc = self.restore(output, dest, expect=None)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertFalse(dest.exists())
        self.assertIn("parent", proc.stderr)

    def test_nonfinite_max_age_is_rejected(self):
        output = self.tmp / "backup.age"
        self.backup(output)
        for value in ("nan", "inf"):
            proc = self.verify(output, extra=("--max-age", value), expect=None)
            self.assertNotEqual(proc.returncode, 0)

    def test_nonzero_trailer_is_rejected(self):
        output = self.tmp / "trailer.age"
        entries = {"gate.json": self.data_bytes, "master_key": self.key_bytes}
        manifest = json.dumps(self.make_manifest(entries)).encode()
        members = [self.regular_member(k, v) for k, v in entries.items()]
        members.append(self.regular_member("manifest.json", manifest))
        plain = self.write_tar(members, self.tmp / "trailer.tar")
        with plain.open("ab") as handle:
            handle.write(b"unexpected-trailer")
        self.encrypt(plain, output)
        proc = self.verify(output, expect=None)
        self.assertNotEqual(proc.returncode, 0, proc.stdout)

    def test_future_manifest_is_rejected(self):
        entries = {"gate.json": self.data_bytes, "master_key": self.key_bytes}
        future = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=2)).isoformat()
        manifest = json.dumps(self.make_manifest(entries, future)).encode()
        members = [self.regular_member(k, v) for k, v in entries.items()]
        members.append(self.regular_member("manifest.json", manifest))
        output = self.craft_archive(members, name="future.age")
        proc = self.verify(output, expect=None)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("future", proc.stderr)


@unittest.skipUnless(_age_installed(), "age/age-keygen not installed")
class RealAgeRoundTripTest(RecoveryHelpers):
    def setUp(self) -> None:
        super().setUp()
        self.age_bin = shutil.which("age")
        self.keygen = shutil.which("age-keygen")
        self.real_identity = self.tmp / "age-key.txt"
        proc = subprocess.run(
            [self.keygen, "-o", str(self.real_identity)],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        public = None
        for line in proc.stderr.splitlines():
            if line.startswith("Public key:"):
                public = line.split(":", 1)[1].strip()
        self.assertIsNotNone(public, proc.stderr)
        self.public = public

    def test_real_age_roundtrip(self):
        archive = self.tmp / "backup.age"
        args = ["backup", "--age-binary", self.age_bin,
                "--data", str(self.data), "--master-key", str(self.key),
                "--include-audit", str(self.audit),
                "--output", str(archive), "-r", self.public]
        proc = self.run_cli(*args)
        self.assertEqual(proc.returncode, 0, proc.stderr)

        proc = self.run_cli("verify", "--age-binary", self.age_bin,
                            "--identity", str(self.real_identity), str(archive))
        self.assertEqual(proc.returncode, 0, proc.stderr)

        dest = self.tmp / "restored"
        proc = self.run_cli("restore", "--age-binary", self.age_bin,
                            "--identity", str(self.real_identity),
                            "--destination", str(dest), str(archive))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual((dest / "gate.json").read_bytes(), self.data_bytes)
        self.assertEqual((dest / "master_key").read_bytes(), self.key_bytes)


if __name__ == "__main__":
    unittest.main()
