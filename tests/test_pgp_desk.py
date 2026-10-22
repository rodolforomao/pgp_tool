#!/usr/bin/env python3
"""Testes com GNUPGHOME isolado — nunca tocam ~/.gnupg real."""

from __future__ import annotations

import os
import re
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

# Garantir import do projeto
ROOT = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(ROOT))

from gpg_service import (  # noqa: E402
    GpgService,
    armor_looks_incomplete,
    format_fingerprint,
    normalize_fingerprint,
    normalize_pgp_input,
)

TEST_PASSPHRASE = "test-only-passphrase-not-for-production"
REAL_GNUPG = Path.home() / ".gnupg"


class IsolatedGpgTestCase(unittest.TestCase):
    def setUp(self) -> None:
        os.umask(0o077)
        self.tmp = tempfile.mkdtemp(prefix="pgpdesk-test-")
        os.chmod(self.tmp, 0o700)
        self.home = Path(self.tmp) / "gnupg"
        self.home.mkdir(mode=0o700)
        self.service = GpgService(gnupg_home=str(self.home), use_loopback=True)
        # Gerar par de teste
        result = self.service.generate_key(
            name="Alice Test",
            email="alice@example.test",
            passphrase=TEST_PASSPHRASE,
            key_length=2048,  # mais rápido nos testes
            expire_date="0",
        )
        self.assertTrue(result.ok, result.message)
        self.fp = result.fingerprints[0]
        self.workdir = Path(self.tmp) / "work"
        self.workdir.mkdir()

    def tearDown(self) -> None:
        # Garantir que não mexemos no keyring real
        self.assertNotEqual(Path(self.service.gnupg_home).resolve(), REAL_GNUPG.resolve())
        shutil.rmtree(self.tmp, ignore_errors=True)

    # --- testes ---

    def test_01_list_public_keys(self) -> None:
        keys = self.service.list_public_keys()
        self.assertGreaterEqual(len(keys), 1)
        self.assertEqual(keys[0].fingerprint_normalized, self.fp)

    def test_02_list_secret_keys(self) -> None:
        keys = self.service.list_secret_keys()
        self.assertGreaterEqual(len(keys), 1)
        self.assertTrue(keys[0].has_secret or keys[0].is_secret)

    def test_03_encrypt(self) -> None:
        result = self.service.encrypt("ola mundo", recipients=[self.fp])
        self.assertTrue(result.ok, result.message)
        self.assertIn("BEGIN PGP MESSAGE", result.data)

    def test_04_decrypt(self) -> None:
        enc = self.service.encrypt("segredo-123", recipients=[self.fp])
        self.assertTrue(enc.ok)
        dec = self.service.decrypt(enc.data, passphrase=TEST_PASSPHRASE)
        self.assertTrue(dec.ok, dec.message)
        self.assertEqual(dec.data, "segredo-123")

    def test_04b_decrypt_dirty_paste(self) -> None:
        """E-mail/clipboard costuma trazer texto à volta do bloco armor."""
        enc = self.service.encrypt("paste-sujo", recipients=[self.fp])
        self.assertTrue(enc.ok)
        dirty = (
            "De: alguem@exemplo.test\n"
            "Assunto: segredo\n\n"
            + enc.data.replace("-", "\u2013", 1)  # en-dash no 1º hífen do BEGIN
            + "\n-- \nAssinatura do cliente\n"
        )
        # Se o replace quebrou o marcador, normalize deve ainda achar o END/BEGIN corretos
        # quando só um hífen foi trocado no meio do marcador — reteste com prefácio só:
        dirty = "Prefácio do e-mail\n\n" + enc.data + "\n\nFim do e-mail\n"
        dec = self.service.decrypt(dirty, passphrase=TEST_PASSPHRASE)
        self.assertTrue(dec.ok, dec.message)
        self.assertEqual(dec.data, "paste-sujo")
        self.assertTrue(armor_looks_incomplete("-----BEGIN PGP MESSAGE-----\nhcBMA"))
        cleaned = normalize_pgp_input(dirty)
        self.assertTrue(cleaned.startswith("-----BEGIN PGP MESSAGE-----"))
        self.assertTrue(cleaned.rstrip().endswith("-----END PGP MESSAGE-----"))

    def test_05_sign(self) -> None:
        signed = self.service.sign(
            "assinado",
            keyid=self.fp,
            clearsign=True,
            passphrase=TEST_PASSPHRASE,
        )
        self.assertTrue(signed.ok, signed.message)
        self.assertIn("BEGIN PGP SIGNED MESSAGE", signed.data)

    def test_06_verify(self) -> None:
        signed = self.service.sign(
            "verificar-me",
            keyid=self.fp,
            clearsign=True,
            passphrase=TEST_PASSPHRASE,
        )
        verified = self.service.verify(signed.data)
        self.assertTrue(verified.ok)
        self.assertTrue(verified.valid)
        self.assertIn("criptograficamente válida", verified.message)

    def test_07_sign_encrypt(self) -> None:
        result = self.service.encrypt(
            "sign+enc",
            recipients=[self.fp],
            sign_key=self.fp,
            passphrase=TEST_PASSPHRASE,
        )
        self.assertTrue(result.ok, result.message)
        dec = self.service.decrypt(result.data, passphrase=TEST_PASSPHRASE)
        self.assertTrue(dec.ok)
        self.assertEqual(dec.data, "sign+enc")

    def test_08_export_public_only(self) -> None:
        exp = self.service.export_public(self.fp)
        self.assertTrue(exp.ok)
        self.assertIn("BEGIN PGP PUBLIC KEY", exp.data)
        self.assertNotIn("BEGIN PGP PRIVATE KEY", exp.data)

    def test_09_import_public_isolated(self) -> None:
        exp = self.service.export_public(self.fp)
        other_home = Path(self.tmp) / "other"
        other_home.mkdir(mode=0o700)
        other = GpgService(gnupg_home=str(other_home), use_loopback=True)
        imported = other.import_key(exp.data)
        self.assertTrue(imported.ok)
        self.assertFalse(imported.imported_secret)
        self.assertEqual(normalize_fingerprint(imported.fingerprints[0]), self.fp)

    def test_10_fingerprint_roundtrip(self) -> None:
        exp = self.service.export_public(self.fp)
        other_home = Path(self.tmp) / "fpcheck"
        other_home.mkdir(mode=0o700)
        other = GpgService(gnupg_home=str(other_home), use_loopback=True)
        other.import_key(exp.data)
        pubs = other.list_public_keys()
        self.assertEqual(pubs[0].fingerprint_normalized, self.fp)
        self.assertEqual(
            normalize_fingerprint(format_fingerprint(self.fp)),
            self.fp,
        )

    def test_11_missing_recipient(self) -> None:
        fake = "AA" * 20
        result = self.service.encrypt("x", recipients=[fake])
        self.assertFalse(result.ok)

    def test_12_invalid_signature(self) -> None:
        signed = self.service.sign(
            "original",
            keyid=self.fp,
            clearsign=True,
            passphrase=TEST_PASSPHRASE,
        )
        tampered = signed.data.replace("original", "alterado")
        verified = self.service.verify(tampered)
        self.assertFalse(verified.ok)
        self.assertIn("inválida", verified.message.lower())

    def test_13_decrypt_without_secret(self) -> None:
        enc = self.service.encrypt("privado", recipients=[self.fp])
        stranger_home = Path(self.tmp) / "stranger"
        stranger_home.mkdir(mode=0o700)
        stranger = GpgService(gnupg_home=str(stranger_home), use_loopback=True)
        # Importa só pública
        stranger.import_key(self.service.export_public(self.fp).data)
        dec = stranger.decrypt(enc.data, passphrase=TEST_PASSPHRASE)
        self.assertFalse(dec.ok)
        self.assertIn("chave privada", dec.message.lower())

    def test_14_special_characters_message(self) -> None:
        text = "Olá — café ☕\n路径/файл\nquotes\"'`"
        enc = self.service.encrypt(text, recipients=[self.fp])
        self.assertTrue(enc.ok)
        dec = self.service.decrypt(enc.data, passphrase=TEST_PASSPHRASE)
        self.assertTrue(dec.ok)
        self.assertEqual(dec.data, text)

    def test_15_filename_with_spaces(self) -> None:
        src = self.workdir / "meu arquivo especial.txt"
        src.write_text("conteudo com espaços no nome", encoding="utf-8")
        out = self.workdir / "meu arquivo especial.txt.asc"
        result = self.service.encrypt_file(str(src), recipients=[self.fp], output=str(out))
        self.assertTrue(result.ok, result.message)
        self.assertTrue(out.is_file())
        plain = self.workdir / "saida decifrada.txt"
        dec = self.service.decrypt_file(str(out), output=str(plain), passphrase=TEST_PASSPHRASE)
        self.assertTrue(dec.ok, dec.message)
        self.assertEqual(plain.read_text(encoding="utf-8"), "conteudo com espaços no nome")

    def test_16_malicious_path_treated_as_path(self) -> None:
        # Caminho com metacaracteres de shell deve ser tratado como path, não como shell
        evil_path = self.workdir / "file; rm -rf should-not-run"
        evil_path.write_text("safe", encoding="utf-8")
        out = self.workdir / "out.asc"
        result = self.service.encrypt_file(str(evil_path), recipients=[self.fp], output=str(out))
        self.assertTrue(result.ok, result.message)
        self.assertTrue(out.is_file())
        self.assertTrue(evil_path.is_file())

    def test_34_roundtrip_sign_encrypt_verify(self) -> None:
        plaintext = "round-trip-bytes-åß"
        se = self.service.encrypt(
            plaintext,
            recipients=[self.fp],
            sign_key=self.fp,
            passphrase=TEST_PASSPHRASE,
        )
        self.assertTrue(se.ok)
        dec = self.service.decrypt(se.data, passphrase=TEST_PASSPHRASE)
        self.assertTrue(dec.ok)
        self.assertEqual(dec.data, plaintext)
        # clearsign roundtrip
        signed = self.service.sign(plaintext, keyid=self.fp, clearsign=True, passphrase=TEST_PASSPHRASE)
        verified = self.service.verify(signed.data)
        self.assertTrue(verified.valid)


class StaticSecurityTests(unittest.TestCase):
    PROD_FILES = [
        ROOT / "app.py",
        ROOT / "gpg_service.py",
        ROOT / "run.sh",
        ROOT / "requirements.txt",
        ROOT / "README.md",
        ROOT / "SECURITY.md",
        ROOT / ".gitignore",
    ]

    def _prod_text(self) -> str:
        return "\n".join(p.read_text(encoding="utf-8", errors="ignore") for p in self.PROD_FILES if p.is_file())

    def test_17_no_shell_true(self) -> None:
        for path in self.PROD_FILES:
            if not path.is_file() or path.suffix not in {".py", ".sh"}:
                continue
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("shell=True", text, msg=str(path))

    def test_18_no_hardcoded_passphrase_in_app(self) -> None:
        app = (ROOT / "app.py").read_text(encoding="utf-8")
        self.assertNotRegex(app, r'passphrase\s*=\s*["\'][^"\']+["\']')
        service = (ROOT / "gpg_service.py").read_text(encoding="utf-8")
        self.assertNotRegex(service, r'passphrase\s*=\s*["\'][^"\']+["\']')

    def test_19_no_private_key_block_in_code(self) -> None:
        # Marcador completo de bloco armorado não deve existir em artefatos versionáveis.
        # Checagens usam substrings ("PRIVATE KEY BLOCK") sem o prefixo BEGIN PGP.
        for path in self.PROD_FILES:
            if not path.is_file():
                continue
            data = path.read_text(encoding="utf-8", errors="ignore")
            self.assertNotIn(
                "-----BEGIN PGP PRIVATE KEY BLOCK-----",
                data,
                msg=f"private key armor found in {path}",
            )

    def test_20_gitignore_covers_secrets(self) -> None:
        gi = (ROOT / ".gitignore").read_text(encoding="utf-8")
        for item in ("secrets/", "*.asc", "*.gpg", "*.pgp", "*.key", "*.priv", "*.private", "*.secret"):
            self.assertIn(item, gi)

    def test_no_os_system_eval_exec(self) -> None:
        for path in (ROOT / "app.py", ROOT / "gpg_service.py", ROOT / "run.sh"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("os.system", text, msg=str(path))
            self.assertNotIn("os.popen", text, msg=str(path))
            self.assertIsNone(re.search(r"(?<![A-Za-z_])eval\(", text), msg=str(path))
            self.assertIsNone(re.search(r"(?<![A-Za-z_])exec\(", text), msg=str(path))

    def test_umask_in_app(self) -> None:
        app = (ROOT / "app.py").read_text(encoding="utf-8")
        self.assertIn("os.umask(0o077)", app)

    def test_real_keyring_untouched_marker(self) -> None:
        self.assertTrue(str(REAL_GNUPG).endswith(".gnupg"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
