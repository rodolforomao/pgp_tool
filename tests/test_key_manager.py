#!/usr/bin/env python3
"""Testes do gerenciador/descoberta de chaves — GNUPGHOME temporário apenas."""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gpg_service import (  # noqa: E402
    GpgService,
    format_fingerprint,
    normalize_fingerprint,
    write_secure_file,
)

TEST_PASSPHRASE = "test-only-passphrase-not-for-production"
REAL_GNUPG = Path.home() / ".gnupg"


class KeyManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        os.umask(0o077)
        self.tmp = tempfile.mkdtemp(prefix="pgpdesk-km-")
        os.chmod(self.tmp, 0o700)
        self.home = Path(self.tmp) / "gnupg"
        self.home.mkdir(mode=0o700)
        self.service = GpgService(gnupg_home=str(self.home), use_loopback=True)
        result = self.service.generate_key(
            name="Alice Test",
            email="alice@example.test",
            passphrase=TEST_PASSPHRASE,
            key_length=2048,
            expire_date="0",
        )
        self.assertTrue(result.ok, result.message)
        self.fp = normalize_fingerprint(result.fingerprints[0])
        self.workdir = Path(self.tmp) / "work"
        self.workdir.mkdir()

    def tearDown(self) -> None:
        self.assertNotEqual(Path(self.service.gnupg_home).resolve(), REAL_GNUPG.resolve())
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_01_create_key(self) -> None:
        self.assertTrue(self.fp)
        self.assertEqual(len(self.fp), 40)

    def test_02_list_key(self) -> None:
        keys = self.service.list_public_keys()
        self.assertGreaterEqual(len(keys), 1)
        self.assertEqual(keys[0].fingerprint_normalized, self.fp)

    def test_03_fingerprint_format(self) -> None:
        display = format_fingerprint(self.fp)
        self.assertEqual(normalize_fingerprint(display), self.fp)
        self.assertIn(" ", display)

    def test_04_export_public(self) -> None:
        out = self.workdir / "alice-public.asc"
        result = self.service.save_export_file(self.fp, out, secret=False)
        self.assertTrue(result.ok, result.message)
        self.assertTrue(out.is_file())
        self.assertGreater(out.stat().st_size, 0)
        text = out.read_text(encoding="utf-8")
        self.assertIn("BEGIN PGP PUBLIC KEY", text)
        self.assertNotIn("PRIVATE KEY BLOCK", text)

    def test_05_import_public_other_home(self) -> None:
        pub = self.service.export_public(self.fp)
        other_home = Path(self.tmp) / "other"
        other_home.mkdir(mode=0o700)
        other = GpgService(gnupg_home=str(other_home), use_loopback=True)
        imported = other.import_key(pub.data)
        self.assertTrue(imported.ok)
        self.assertFalse(imported.imported_secret)
        self.assertEqual(normalize_fingerprint(imported.fingerprints[0]), self.fp)

    def test_06_export_private_backup(self) -> None:
        out = self.workdir / "alice-private-backup.asc"
        result = self.service.save_export_file(
            self.fp, out, secret=True, passphrase=TEST_PASSPHRASE
        )
        self.assertTrue(result.ok, result.message)
        self.assertTrue(out.is_file())
        self.assertEqual(result.data, "")  # não deve devolver material privado
        head = out.read_bytes()[:80]
        self.assertIn(b"PRIVATE KEY", head)

    def test_07_import_private_backup_other_home(self) -> None:
        out = self.workdir / "restore-me.asc"
        exp = self.service.save_export_file(
            self.fp, out, secret=True, passphrase=TEST_PASSPHRASE
        )
        self.assertTrue(exp.ok, exp.message)
        other_home = Path(self.tmp) / "restore"
        other_home.mkdir(mode=0o700)
        other = GpgService(gnupg_home=str(other_home), use_loopback=True)
        imported = other.import_key_file(str(out))
        self.assertTrue(imported.ok, imported.message)
        self.assertTrue(imported.imported_secret)
        secs = other.list_secret_keys()
        self.assertTrue(any(k.fingerprint_normalized == self.fp for k in secs))

    def test_08_fingerprint_before_after(self) -> None:
        out = self.workdir / "fp-check.asc"
        self.service.save_export_file(self.fp, out, secret=False)
        keys = self.service.inspect_key_file(out)
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0].fingerprint_normalized, self.fp)

    def test_09_detect_duplicate(self) -> None:
        out = self.workdir / "dup.asc"
        self.service.save_export_file(self.fp, out, secret=False)
        found = self.service.inspect_key_file(out)
        self.assertTrue(found[0].already_in_keyring)

    def test_10_scan_does_not_modify_keyring(self) -> None:
        before = self.service.keyring_fingerprints()
        folder = self.workdir / "scan me"
        folder.mkdir()
        pub = self.workdir / "scan me" / "pub.asc"
        self.service.save_export_file(self.fp, pub, secret=False)
        # ficheiro inválido com extensão .asc
        (folder / "lixo.asc").write_text("isto nao e pgp", encoding="utf-8")
        result = self.service.discover_keys(include_keyring=True, directories=[folder])
        after = self.service.keyring_fingerprints()
        self.assertEqual(before, after)
        self.assertTrue(result.ok)
        self.assertTrue(any(d.fingerprint_normalized == self.fp for d in result.discovered))

    def test_11_backup_permissions(self) -> None:
        out = self.workdir / "perm-private.asc"
        result = self.service.save_export_file(
            self.fp, out, secret=True, passphrase=TEST_PASSPHRASE
        )
        self.assertTrue(result.ok, result.message)
        mode = out.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_12_path_with_spaces(self) -> None:
        folder = self.workdir / "pasta com espaços"
        folder.mkdir()
        out = folder / "chave publica.asc"
        result = self.service.save_export_file(self.fp, out, secret=False)
        self.assertTrue(result.ok, result.message)
        keys = self.service.inspect_key_file(out)
        self.assertEqual(keys[0].fingerprint_normalized, self.fp)

    def test_13_unicode_identity(self) -> None:
        # Mensagem unicode no encrypt (já coberto noutros testes); aqui UID com nome ASCII seguro
        # e conteúdo de ficheiro com unicode no path
        folder = self.workdir / "café-文档"
        folder.mkdir()
        out = folder / "chave-ünicode.asc"
        result = self.service.save_export_file(self.fp, out, secret=False)
        self.assertTrue(result.ok, result.message)
        self.assertTrue(out.is_file())

    def test_14_invalid_asc_rejected(self) -> None:
        bad = self.workdir / "fake.asc"
        bad.write_text("-----BEGIN PGP PUBLIC KEY BLOCK-----\nnot-a-key\n", encoding="utf-8")
        keys = self.service.inspect_key_file(bad)
        self.assertEqual(keys, [])

    def test_15_public_without_private_in_file(self) -> None:
        out = self.workdir / "only-pub.asc"
        self.service.save_export_file(self.fp, out, secret=False)
        keys = self.service.inspect_key_file(out)
        self.assertTrue(keys)
        self.assertTrue(keys[0].has_public)
        self.assertFalse(keys[0].has_private)

    def test_16_file_with_private_material(self) -> None:
        out = self.workdir / "with-priv.asc"
        self.service.save_export_file(
            self.fp, out, secret=True, passphrase=TEST_PASSPHRASE
        )
        keys = self.service.inspect_key_file(out)
        self.assertTrue(keys)
        self.assertTrue(keys[0].has_private)
        self.assertEqual(keys[0].fingerprint_normalized, self.fp)

    def test_17_write_secure_file_mode(self) -> None:
        path = self.workdir / "secure.txt"
        write_secure_file(path, "hello")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_18_protected_backup_is_message(self) -> None:
        out = self.workdir / "protected.asc"
        result = self.service.save_export_file(
            self.fp, out, secret=True, protected=True, passphrase=TEST_PASSPHRASE
        )
        self.assertTrue(result.ok, result.message)
        data = out.read_text(encoding="utf-8")
        self.assertIn("BEGIN PGP MESSAGE", data)
        self.assertNotIn("PRIVATE KEY BLOCK", data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
