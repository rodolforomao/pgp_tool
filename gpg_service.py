"""Camada de operações PGP/GPG via GnuPG do sistema (sem criptografia própria)."""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import gnupg

logger = logging.getLogger("pgp_desk.gpg")

ALGO_NAMES = {
    "1": "RSA",
    "16": "ElGamal",
    "17": "DSA",
    "18": "ECDH",
    "19": "ECDSA",
    "22": "EdDSA",
}


def normalize_fingerprint(value: str) -> str:
    """Normaliza fingerprint para hex maiúsculo sem espaços."""
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", value or "")
    return cleaned.upper()


def format_fingerprint(value: str) -> str:
    """Formata fingerprint em grupos de 4: 'XXXX XXXX ...'."""
    fp = normalize_fingerprint(value)
    if not fp:
        return ""
    return " ".join(fp[i : i + 4] for i in range(0, len(fp), 4))


def parse_uid(uid: str) -> tuple[str, str]:
    """Extrai (nome, email) de um UID OpenPGP."""
    if not uid:
        return "", ""
    match = re.match(r"^(.*?)\s*<([^>]+)>\s*$", uid.strip())
    if match:
        return match.group(1).strip(), match.group(2).strip()
    if "@" in uid and " " not in uid.strip():
        return "", uid.strip()
    return uid.strip(), ""


def _to_text(data) -> str:
    """Converte saída do python-gnupg (bytes|str) em texto sem usar str(bytes)."""
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    if isinstance(data, str):
        return data
    return str(data)


# Traços/hífens unicode comuns em paste de e-mail/Word → ASCII
_DASH_TRANSLATION = str.maketrans({
    "\u2010": "-",  # hyphen
    "\u2011": "-",  # non-breaking hyphen
    "\u2012": "-",  # figure dash
    "\u2013": "-",  # en dash
    "\u2014": "-",  # em dash
    "\u2212": "-",  # minus
    "\ufeff": "",   # BOM
    "\u00a0": " ",  # nbsp
})

_ARMOR_RE = re.compile(
    r"-----BEGIN PGP ([A-Z0-9 ]+)-----"
    r".*?"
    r"-----END PGP \1-----",
    re.DOTALL,
)


_CLEARSIGN_RE = re.compile(
    r"-----BEGIN PGP SIGNED MESSAGE-----.*?-----END PGP SIGNATURE-----",
    re.DOTALL,
)


def normalize_pgp_input(data: str) -> str:
    """Limpa paste comum e extrai o primeiro bloco ASCII-armor completo, se houver.

    Aceita texto com prefácio (e-mail, citações). Se não houver bloco completo,
    devolve o texto normalizado (traços unicode → ASCII, CRLF → LF).

    Clearsign (SIGNED MESSAGE + SIGNATURE) é preservado intacto — não extrair
    só o bloco SIGNATURE, senão o GnuPG reporta "no signed data".
    """
    if not data:
        return ""
    text = _to_text(data).translate(_DASH_TRANSLATION)
    text = text.replace("\r\n", "\n").replace("\r", "\n").strip()

    clearsign = _CLEARSIGN_RE.search(text)
    if clearsign:
        return clearsign.group(0).strip() + "\n"

    # Preferir MESSAGE para decrypt; senão o primeiro bloco armor encontrado
    preferred = (
        "MESSAGE",
        "PUBLIC KEY BLOCK",
        "PRIVATE KEY BLOCK",
        "SECRET KEY BLOCK",
        "SIGNATURE",
        "ARMORED FILE",
    )
    matches = list(_ARMOR_RE.finditer(text))
    if not matches:
        return text
    by_kind = {m.group(1): m.group(0) for m in matches}
    for kind in preferred:
        if kind in by_kind:
            return by_kind[kind].strip() + "\n"
    return matches[0].group(0).strip() + "\n"


def armor_looks_incomplete(data: str) -> bool:
    """True se há BEGIN sem END correspondente (paste truncado)."""
    text = _to_text(data).translate(_DASH_TRANSLATION)
    if "-----BEGIN PGP " not in text:
        return False
    return _ARMOR_RE.search(text) is None


def humanize_gpg_error(stderr: str = "", status: str = "") -> str:
    """Traduz erros conhecidos do GnuPG para mensagens úteis."""
    text = f"{stderr}\n{status}".lower()
    mapping = [
        (
            "no secret key",
            "Não foi encontrada no seu keyring uma chave privada "
            "capaz de descriptografar esta mensagem.",
        ),
        (
            "bad passphrase",
            "A autenticação da chave privada falhou "
            "(frase-senha incorreta ou cancelada no gpg-agent).",
        ),
        (
            "passphrase",
            "A autenticação da chave privada falhou ou foi cancelada no gpg-agent.",
        ),
        (
            "no public key",
            "Não foi encontrada a chave pública necessária no keyring.",
        ),
        (
            "unusable public key",
            "A chave pública selecionada não pode ser usada para esta operação.",
        ),
        (
            "no valid openpgp data",
            "Os dados fornecidos não parecem ser um bloco OpenPGP válido.\n"
            "Confirme que colou o bloco completo "
            "(de -----BEGIN PGP… até -----END PGP…), sem cortes.",
        ),
        (
            "decryption failed",
            "A descriptografia falhou. Verifique se a mensagem é para uma das suas chaves.",
        ),
        (
            "invalid recipient",
            "Destinatário inválido ou chave pública não utilizável.",
        ),
        (
            "agent",
            "Problema de comunicação com o gpg-agent. "
            "Verifique se o agente está em execução e se o pinentry está configurado.",
        ),
        (
            "pinentry",
            "Não foi possível obter autenticação via pinentry/gpg-agent.",
        ),
        (
            "cancelled",
            "Operação cancelada pelo utilizador.",
        ),
        (
            "canceled",
            "Operação cancelada pelo utilizador.",
        ),
    ]
    for needle, message in mapping:
        if needle in text:
            return message
    if stderr.strip():
        # Resumo curto, sem dump completo
        first = stderr.strip().splitlines()[0][:240]
        return f"A operação GnuPG falhou: {first}"
    if status.strip():
        return f"A operação GnuPG falhou (status: {status})."
    return "A operação GnuPG falhou por um motivo desconhecido."


@dataclass
class KeyInfo:
    fingerprint: str
    keyid: str
    uids: list[str]
    name: str
    email: str
    algo: str
    length: str
    created: str
    expires: str
    is_secret: bool
    has_secret: bool = False

    @property
    def fingerprint_normalized(self) -> str:
        return normalize_fingerprint(self.fingerprint)

    @property
    def fingerprint_display(self) -> str:
        return format_fingerprint(self.fingerprint)

    @property
    def key_type_label(self) -> str:
        if self.is_secret or self.has_secret:
            return "PRIVATE KEY (+ pública)" if self.has_secret or self.is_secret else "PRIVATE KEY"
        return "PUBLIC KEY"

    @property
    def availability_label(self) -> str:
        if self.is_secret or self.has_secret:
            return "✓ chave privada disponível"
        return "somente chave pública"

    @property
    def label(self) -> str:
        who = self.name or "(sem nome)"
        mail = f" <{self.email}>" if self.email else ""
        kind = "PRIV" if (self.is_secret or self.has_secret) else "PUB"
        return f"[{kind}] {who}{mail} | {self.fingerprint_display}"

    def identity_block(self, title: str = "Chave") -> str:
        return (
            f"{title}:\n"
            f"Nome: {self.name or '(não informado)'}\n"
            f"E-mail: {self.email or '(não informado)'}\n"
            f"Fingerprint:\n{self.fingerprint_display}"
        )


@dataclass
class DiscoveredKey:
    """Metadados de uma chave encontrada (varredura somente leitura — sem material privado)."""

    fingerprint: str
    name: str = ""
    email: str = ""
    algo: str = ""
    length: str = ""
    created: str = ""
    expires: str = ""
    has_public: bool = True
    has_private: bool = False
    source: str = ""
    already_in_keyring: bool = False
    keyring_has_secret: bool = False
    uids: list[str] = field(default_factory=list)

    @property
    def fingerprint_normalized(self) -> str:
        return normalize_fingerprint(self.fingerprint)

    @property
    def fingerprint_display(self) -> str:
        return format_fingerprint(self.fingerprint)

    @property
    def type_label(self) -> str:
        if self.has_private:
            return "Pública + privada"
        return "Pública"

    @property
    def availability_label(self) -> str:
        if self.already_in_keyring:
            if self.keyring_has_secret or self.has_private:
                return "✓ Já disponível (com privada)"
            return "✓ Já disponível"
        if self.has_private:
            return "Privada disponível no ficheiro"
        return "Somente pública no ficheiro"

    def identity_block(self, title: str = "Chave encontrada") -> str:
        return (
            f"{title}:\n"
            f"Nome: {self.name or '(não informado)'}\n"
            f"E-mail: {self.email or '(não informado)'}\n"
            f"Fingerprint:\n{self.fingerprint_display}\n"
            f"Tipo: {self.type_label}\n"
            f"Origem:\n{self.source or '(desconhecida)'}"
        )


@dataclass
class OpResult:
    ok: bool
    data: str = ""
    status: str = ""
    stderr: str = ""
    fingerprints: list[str] = field(default_factory=list)
    username: str = ""
    valid: Optional[bool] = None
    message: str = ""
    technical: str = ""
    imported_secret: bool = False
    key_infos: list[KeyInfo] = field(default_factory=list)
    discovered: list[DiscoveredKey] = field(default_factory=list)


# Extensões candidatas a ficheiros de chave (conteúdo sempre validado).
KEY_FILE_SUFFIXES = {".asc", ".pgp", ".gpg", ".key"}

# Diretórios de sistema / ruído a ignorar na varredura de pastas.
_SKIP_DIR_NAMES = {
    "proc",
    "sys",
    "dev",
    "run",
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".cache",
    ".local",
    ".npm",
    ".cargo",
    "dist",
    "build",
}


def default_key_search_roots() -> list[Path]:
    """Locais razoáveis para procurar ficheiros de chave (nunca /)."""
    home = Path.home()
    names = (
        "Desktop",
        "Área de Trabalho",
        "Documents",
        "Documentos",
        "Downloads",
    )
    roots: list[Path] = []
    seen: set[Path] = set()
    for name in names:
        path = (home / name).expanduser()
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if path.is_dir() and resolved not in seen:
            roots.append(path)
            seen.add(resolved)
    # xdg-user-dir quando disponível
    for xdg_key in ("DESKTOP", "DOCUMENTS", "DOWNLOAD"):
        try:
            out = subprocess.run(
                ["xdg-user-dir", xdg_key],
                capture_output=True,
                text=True,
                check=False,
            )
            if out.returncode == 0 and out.stdout.strip():
                path = Path(out.stdout.strip())
                try:
                    resolved = path.resolve()
                except OSError:
                    continue
                if path.is_dir() and resolved not in seen:
                    roots.append(path)
                    seen.add(resolved)
        except OSError:
            continue
    return roots


def write_secure_file(path: str | Path, data: str | bytes) -> Path:
    """Escreve ficheiro com permissões 0600 desde a criação (sem janela 0644)."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(target.parent, 0o700)
    except OSError:
        pass
    payload = data.encode("utf-8") if isinstance(data, str) else data
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(target), flags, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(payload)
        fh.flush()
        os.fsync(fh.fileno())
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass
    return target

    def user_message(self) -> str:
        if self.message:
            return self.message
        if self.ok:
            return self.status or "Operação concluída."
        return humanize_gpg_error(self.stderr, self.status)


@dataclass
class EnvCheck:
    ok: bool
    gpg_path: str = ""
    version: str = ""
    gnupg_home: str = ""
    keyring_ok: bool = False
    agent_ok: bool = False
    public_count: int = 0
    secret_count: int = 0
    details: list[str] = field(default_factory=list)


class GpgService:
    """Fachada segura sobre o GnuPG do sistema."""

    def __init__(
        self,
        gnupg_home: Optional[str] = None,
        *,
        use_loopback: bool = False,
    ) -> None:
        gpg_bin = shutil.which("gpg")
        if not gpg_bin:
            raise FileNotFoundError(
                "GnuPG não foi encontrado.\n\nInstale o GnuPG e tente novamente."
            )

        home = gnupg_home or os.environ.get("GNUPGHOME") or str(Path.home() / ".gnupg")
        Path(home).mkdir(mode=0o700, exist_ok=True)
        try:
            os.chmod(home, 0o700)
        except OSError:
            pass

        self.gpg_binary = gpg_bin
        self.gnupg_home = home
        self.use_loopback = use_loopback

        options: list[str] = []
        if use_loopback:
            # Apenas para testes isolados / ambientes sem pinentry interativo.
            options.extend(["--pinentry-mode", "loopback"])

        self.gpg = gnupg.GPG(
            gpgbinary=gpg_bin,
            gnupghome=home,
            options=options or None,
        )
        self.gpg.encoding = "utf-8"
        logger.info(
            "GpgService iniciado home=%s loopback=%s",
            home,
            use_loopback,
        )

    # ---------- ambiente ----------

    def check_gpg_environment(self) -> EnvCheck:
        details: list[str] = []
        version = ""
        agent_ok = False
        keyring_ok = False
        pub_n = 0
        sec_n = 0

        try:
            proc = subprocess.run(
                [self.gpg_binary, "--version"],
                check=False,
                capture_output=True,
                text=True,
                shell=False,
            )
            version = (proc.stdout or "").splitlines()[0] if proc.stdout else ""
            details.append(f"Versão: {version or 'desconhecida'}")
        except OSError as exc:
            return EnvCheck(
                ok=False,
                gpg_path=self.gpg_binary,
                gnupg_home=self.gnupg_home,
                details=[f"Falha ao executar gpg: {exc}"],
            )

        try:
            pubs = self.list_public_keys()
            secs = self.list_secret_keys()
            pub_n, sec_n = len(pubs), len(secs)
            keyring_ok = True
            details.append(f"Keyring acessível em {self.gnupg_home}")
            details.append(f"Chaves públicas: {pub_n}")
            details.append(f"Chaves privadas: {sec_n}")
        except Exception as exc:  # noqa: BLE001
            details.append(f"Keyring inacessível: {exc}")

        try:
            proc = subprocess.run(
                [self.gpg_binary, "--batch", "--list-keys"],
                check=False,
                capture_output=True,
                text=True,
                shell=False,
                env={**os.environ, "GNUPGHOME": self.gnupg_home},
            )
            # gpg-agent costuma ser iniciado sob demanda; ausência não é fatal.
            agent_probe = subprocess.run(
                ["gpg-connect-agent", "--quiet", "/bye"],
                check=False,
                capture_output=True,
                text=True,
                shell=False,
                env={**os.environ, "GNUPGHOME": self.gnupg_home},
            )
            agent_ok = agent_probe.returncode == 0
            if agent_ok:
                details.append("gpg-agent: disponível")
            else:
                details.append(
                    "gpg-agent: não confirmado (o GnuPG pode iniciá-lo sob demanda)"
                )
            _ = proc  # silence lint
        except FileNotFoundError:
            details.append("gpg-connect-agent não encontrado; o agente pode ainda funcionar via gpg")
        except OSError as exc:
            details.append(f"Falha ao sondar gpg-agent: {exc}")

        ok = bool(version) and keyring_ok
        return EnvCheck(
            ok=ok,
            gpg_path=self.gpg_binary,
            version=version,
            gnupg_home=self.gnupg_home,
            keyring_ok=keyring_ok,
            agent_ok=agent_ok,
            public_count=pub_n,
            secret_count=sec_n,
            details=details,
        )

    # ---------- chaves ----------

    def list_public_keys(self) -> list[KeyInfo]:
        secret_fps = {
            normalize_fingerprint(k.get("fingerprint") or "")
            for k in self.gpg.list_keys(True)
        }
        keys = self._parse_keys(self.gpg.list_keys(), is_secret=False)
        for key in keys:
            key.has_secret = key.fingerprint_normalized in secret_fps
        return keys

    def list_secret_keys(self) -> list[KeyInfo]:
        keys = self._parse_keys(self.gpg.list_keys(True), is_secret=True)
        for key in keys:
            key.has_secret = True
        return keys

    def get_key(self, fingerprint: str, *, secret: bool = False) -> Optional[KeyInfo]:
        fp = normalize_fingerprint(fingerprint)
        keys = self.list_secret_keys() if secret else self.list_public_keys()
        for key in keys:
            if key.fingerprint_normalized == fp:
                return key
        # fallback: procurar em ambas
        for key in self.list_public_keys() + self.list_secret_keys():
            if key.fingerprint_normalized == fp:
                return key
        return None

    def _parse_keys(self, keys, is_secret: bool) -> list[KeyInfo]:
        result: list[KeyInfo] = []
        for k in keys:
            uids = list(k.get("uids") or [])
            name, email = parse_uid(uids[0]) if uids else ("", "")
            algo_code = str(k.get("algo") or "")
            created = self._format_epoch(k.get("date"))
            expires = self._format_epoch(k.get("expires")) or "nunca"
            result.append(
                KeyInfo(
                    fingerprint=normalize_fingerprint(k.get("fingerprint") or ""),
                    keyid=k.get("keyid") or "",
                    uids=uids,
                    name=name,
                    email=email,
                    algo=ALGO_NAMES.get(algo_code, algo_code or "?"),
                    length=str(k.get("length") or ""),
                    created=created,
                    expires=expires,
                    is_secret=is_secret,
                )
            )
        return result

    @staticmethod
    def _format_epoch(value) -> str:
        if value in (None, "", "0", 0):
            return ""
        try:
            ts = int(value)
            return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
        except (TypeError, ValueError, OSError, OverflowError):
            return str(value)

    def import_key(self, data: str | bytes) -> OpResult:
        logger.info("operação=import_key início")
        looks_secret = False
        sample = _to_text(data)
        # Detecção por marcadores OpenPGP (não é material de chave embutido).
        if "PRIVATE KEY BLOCK" in sample or "SECRET KEY BLOCK" in sample:
            looks_secret = True

        imported = self.gpg.import_keys(data)
        fps = [normalize_fingerprint(f) for f in (imported.fingerprints or []) if f]
        ok = bool(imported.count)
        infos: list[KeyInfo] = []
        for fp in fps:
            info = self.get_key(fp) or self.get_key(fp, secret=True)
            if info:
                infos.append(info)

        has_secret = looks_secret or any(i.has_secret or i.is_secret for i in infos)
        lines = []
        if ok:
            lines.append("Importação concluída pelo GnuPG.")
        else:
            lines.append("Nenhuma chave nova foi importada.")
        for info in infos:
            lines.append("")
            lines.append(info.identity_block("Chave importada"))
            lines.append(f"Tipo: {'PRIVATE KEY' if (info.is_secret or info.has_secret) else 'PUBLIC KEY'}")
            lines.append(info.availability_label)
        if has_secret:
            lines.append("")
            lines.append(
                "Você está importando uma chave privada.\n"
                "Ela concede capacidade de assinar e/ou descriptografar\n"
                "conforme os recursos da chave."
            )

        logger.info(
            "operação=import_key concluída ok=%s count=%s fps=%s",
            ok,
            imported.count,
            fps,
        )
        return OpResult(
            ok=ok,
            data="\n".join(lines),
            status=str(imported.count),
            fingerprints=fps,
            message="\n".join(lines),
            imported_secret=has_secret,
            key_infos=infos,
            technical=str(imported.results),
        )

    def import_key_file(self, path: str) -> OpResult:
        with open(path, "rb") as fh:
            return self.import_key(fh.read())

    def export_public(self, fingerprint: str) -> OpResult:
        fp = normalize_fingerprint(fingerprint)
        logger.info("operação=export_public fp=%s", fp)
        data = _to_text(self.gpg.export_keys(fp, armor=True))
        ok = bool(data and "PUBLIC KEY BLOCK" in data)
        if data and "PRIVATE KEY BLOCK" in data:
            return OpResult(
                ok=False,
                message="Recusa de segurança: a exportação pública não pode conter material privado.",
            )
        return OpResult(
            ok=ok,
            data=data,
            status="export public",
            fingerprints=[fp],
            message="Chave pública exportada." if ok else "Falha ao exportar chave pública.",
            stderr="" if ok else "export failed",
        )

    def export_secret(self, fingerprint: str, passphrase: Optional[str] = None) -> OpResult:
        """Exporta chave privada. Passphrase só para testes com loopback; GUI usa gpg-agent."""
        fp = normalize_fingerprint(fingerprint)
        logger.info("operação=export_secret fp=%s", fp)
        kwargs = {"secret": True, "armor": True}
        if passphrase is not None:
            kwargs["passphrase"] = passphrase
        data = _to_text(self.gpg.export_keys(fp, **kwargs))
        ok = bool(data and "PRIVATE KEY BLOCK" in data)
        return OpResult(
            ok=ok,
            data=data,
            status="export secret" if ok else "export secret failed",
            fingerprints=[fp],
            message=(
                "Chave privada exportada."
                if ok
                else humanize_gpg_error(status="export secret failed")
            ),
            stderr="" if ok else "export secret failed",
        )

    def generate_key(
        self,
        name: str,
        email: str,
        passphrase: str,
        key_type: str = "RSA",
        key_length: int = 4096,
        expire_date: str = "0",
        comment: str = "",
    ) -> OpResult:
        """Gera chave via GnuPG. A passphrase é usada só nesta chamada (proteção da chave)."""
        logger.info("operação=generate_key início tipo=%s bits=%s", key_type, key_length)
        input_data = self.gpg.gen_key_input(
            key_type=key_type,
            key_length=key_length,
            name_real=name,
            name_email=email,
            name_comment=comment or None,
            passphrase=passphrase,
            expire_date=expire_date,
        )
        key = self.gpg.gen_key(input_data)
        fp = normalize_fingerprint(str(key.fingerprint or ""))
        ok = bool(fp)
        logger.info("operação=generate_key concluída ok=%s fp=%s", ok, fp)
        info = self.get_key(fp, secret=True) if ok else None
        if ok and info:
            msg = (
                "Chave criada com sucesso.\n\n"
                f"Nome:\n{info.name or name}\n\n"
                f"E-mail:\n{info.email or email}\n\n"
                f"Fingerprint:\n{format_fingerprint(fp)}\n\n"
                "A chave privada foi armazenada pelo GnuPG."
            )
        elif ok:
            msg = (
                "Chave criada com sucesso.\n\n"
                f"Fingerprint:\n{format_fingerprint(fp)}\n\n"
                "A chave privada foi armazenada pelo GnuPG."
            )
        else:
            msg = humanize_gpg_error(str(key.stderr or ""), "falha ao gerar")
        return OpResult(
            ok=ok,
            data=fp,
            status="chave gerada" if ok else "falha ao gerar",
            fingerprints=[fp] if fp else [],
            stderr=str(key.stderr or ""),
            message=msg,
            technical=str(key.stderr or ""),
            key_infos=[info] if info else [],
        )

    # ---------- descoberta / varredura (somente leitura) ----------

    def keyring_fingerprints(self) -> dict[str, bool]:
        """Mapa fingerprint → tem material privado no keyring operacional."""
        pubs = {k.fingerprint_normalized for k in self.list_public_keys()}
        secs = {k.fingerprint_normalized for k in self.list_secret_keys()}
        all_fps = pubs | secs
        return {fp: fp in secs for fp in all_fps}

    def discover_from_keyring(self) -> list[DiscoveredKey]:
        """Lista chaves já no keyring GnuPG (sem alterar nada)."""
        found: dict[str, DiscoveredKey] = {}
        for key in self.list_public_keys():
            fp = key.fingerprint_normalized
            found[fp] = DiscoveredKey(
                fingerprint=fp,
                name=key.name,
                email=key.email,
                algo=key.algo,
                length=key.length,
                created=key.created,
                expires=key.expires,
                has_public=True,
                has_private=bool(key.has_secret or key.is_secret),
                source=f"keyring:{self.gnupg_home}",
                already_in_keyring=True,
                keyring_has_secret=bool(key.has_secret or key.is_secret),
                uids=list(key.uids),
            )
        for key in self.list_secret_keys():
            fp = key.fingerprint_normalized
            if fp in found:
                found[fp].has_private = True
                found[fp].keyring_has_secret = True
            else:
                found[fp] = DiscoveredKey(
                    fingerprint=fp,
                    name=key.name,
                    email=key.email,
                    algo=key.algo,
                    length=key.length,
                    created=key.created,
                    expires=key.expires,
                    has_public=True,
                    has_private=True,
                    source=f"keyring:{self.gnupg_home}",
                    already_in_keyring=True,
                    keyring_has_secret=True,
                    uids=list(key.uids),
                )
        return list(found.values())

    def inspect_key_file(self, path: str | Path) -> list[DiscoveredKey]:
        """Lê metadados de um ficheiro via gpg --show-keys (não importa, não altera keyring)."""
        file_path = Path(path)
        if not file_path.is_file():
            return []
        # Homedir temporário: garante que a inspeção nunca toca no keyring operacional.
        with tempfile.TemporaryDirectory(prefix="pgpdesk-inspect-") as tmp:
            try:
                os.chmod(tmp, 0o700)
            except OSError:
                pass
            try:
                proc = subprocess.run(
                    [
                        self.gpg_binary,
                        "--homedir",
                        tmp,
                        "--batch",
                        "--status-fd",
                        "2",
                        "--with-colons",
                        "--with-fingerprint",
                        "--show-keys",
                        str(file_path),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            except OSError as exc:
                logger.info("operação=inspect_key_file falha path=%s err=%s", file_path.name, type(exc).__name__)
                return []

        if proc.returncode not in (0, 2):
            # 2 às vezes aparece com avisos; ainda assim pode haver saída útil.
            if not (proc.stdout or "").strip():
                return []

        parsed = self._parse_show_keys_colon(proc.stdout or "")
        ring = self.keyring_fingerprints()
        results: list[DiscoveredKey] = []
        for item in parsed:
            fp = item.fingerprint_normalized
            if not fp:
                continue
            item.source = str(file_path)
            item.already_in_keyring = fp in ring
            item.keyring_has_secret = bool(ring.get(fp))
            results.append(item)
        logger.info(
            "operação=inspect_key_file path=%s keys=%s",
            file_path.name,
            len(results),
        )
        return results

    def _parse_show_keys_colon(self, colon_out: str) -> list[DiscoveredKey]:
        """Parseia saída --with-colons de --show-keys / --list-keys."""
        by_fp: dict[str, DiscoveredKey] = {}
        current_fp: Optional[str] = None
        pending_kind: Optional[str] = None  # pub | sec
        pending_meta: dict[str, str] = {}

        def ensure(fp: str) -> DiscoveredKey:
            if fp not in by_fp:
                by_fp[fp] = DiscoveredKey(fingerprint=fp)
            return by_fp[fp]

        for raw in colon_out.splitlines():
            parts = raw.split(":")
            if not parts:
                continue
            tag = parts[0]
            if tag in {"pub", "sec", "sub", "ssb"}:
                pending_kind = tag
                pending_meta = {
                    "algo": ALGO_NAMES.get(parts[3], parts[3] or "?") if len(parts) > 3 else "?",
                    "length": parts[2] if len(parts) > 2 else "",
                    "created": self._format_epoch(parts[5]) if len(parts) > 5 else "",
                    "expires": self._format_epoch(parts[6]) if len(parts) > 6 else "",
                }
                if not pending_meta["expires"]:
                    pending_meta["expires"] = "nunca"
            elif tag == "fpr" and len(parts) > 9:
                fp = normalize_fingerprint(parts[9])
                if not fp:
                    continue
                # fpr após sub/ssb: fingerprint de subchave — só marcar presença se sec/ssb
                if pending_kind in {"sub", "ssb"}:
                    if pending_kind == "ssb" and current_fp and current_fp in by_fp:
                        by_fp[current_fp].has_private = True
                    pending_kind = None
                    continue
                current_fp = fp
                key = ensure(fp)
                if pending_kind == "pub":
                    key.has_public = True
                elif pending_kind == "sec":
                    key.has_public = True
                    key.has_private = True
                if pending_meta:
                    key.algo = key.algo or pending_meta.get("algo", "")
                    key.length = key.length or pending_meta.get("length", "")
                    key.created = key.created or pending_meta.get("created", "")
                    key.expires = key.expires or pending_meta.get("expires", "")
                pending_kind = None
            elif tag == "uid" and current_fp:
                uid = ""
                if len(parts) > 9 and parts[9]:
                    uid = parts[9]
                elif len(parts) > 7 and parts[7]:  # fallback raro
                    uid = parts[7]
                if uid:
                    key = ensure(current_fp)
                    if uid not in key.uids:
                        key.uids.append(uid)
                    if not key.name and not key.email:
                        key.name, key.email = parse_uid(uid)
        return list(by_fp.values())

    def scan_directory(
        self,
        directory: str | Path,
        *,
        recursive: bool = True,
        max_files: int = 400,
    ) -> list[DiscoveredKey]:
        """Varre uma pasta por ficheiros candidatos; valida conteúdo com GnuPG (read-only)."""
        root = Path(directory)
        if not root.is_dir():
            return []
        candidates: list[Path] = []
        try:
            if recursive:
                for dirpath, dirnames, filenames in os.walk(root):
                    dirnames[:] = [
                        d
                        for d in dirnames
                        if d not in _SKIP_DIR_NAMES and not d.startswith(".")
                    ]
                    for name in filenames:
                        path = Path(dirpath) / name
                        if path.suffix.lower() in KEY_FILE_SUFFIXES:
                            candidates.append(path)
                        if len(candidates) >= max_files:
                            break
                    if len(candidates) >= max_files:
                        break
            else:
                for path in root.iterdir():
                    if path.is_file() and path.suffix.lower() in KEY_FILE_SUFFIXES:
                        candidates.append(path)
                    if len(candidates) >= max_files:
                        break
        except OSError as exc:
            logger.info("operação=scan_directory erro=%s", type(exc).__name__)
            return []

        merged: dict[str, DiscoveredKey] = {}
        for path in candidates:
            try:
                # Heurística rápida: ficheiros enormes provavelmente não são chaves ASCII
                if path.stat().st_size > 2_000_000:
                    continue
            except OSError:
                continue
            for item in self.inspect_key_file(path):
                fp = item.fingerprint_normalized
                if not fp:
                    continue
                if fp in merged:
                    existing = merged[fp]
                    existing.has_private = existing.has_private or item.has_private
                    existing.has_public = existing.has_public or item.has_public
                    if item.source and item.source not in existing.source:
                        existing.source = f"{existing.source}; {item.source}"
                else:
                    merged[fp] = item
        logger.info(
            "operação=scan_directory root_ok candidates=%s keys=%s",
            len(candidates),
            len(merged),
        )
        return list(merged.values())

    def discover_keys(
        self,
        *,
        include_keyring: bool = True,
        directories: Optional[list[str | Path]] = None,
    ) -> OpResult:
        """
        Varredura somente leitura: keyring + pastas locais razoáveis (ou as indicadas).
        Nunca importa, apaga, exporta privadas ou altera o keyring.
        """
        logger.info("operação=discover_keys início")
        before = self.keyring_fingerprints()
        found: dict[str, DiscoveredKey] = {}

        if include_keyring:
            for item in self.discover_from_keyring():
                found[item.fingerprint_normalized] = item

        roots = directories if directories is not None else default_key_search_roots()
        for root in roots:
            for item in self.scan_directory(root):
                fp = item.fingerprint_normalized
                if fp in found:
                    existing = found[fp]
                    existing.has_private = existing.has_private or item.has_private
                    if item.source and "keyring:" not in (existing.source or ""):
                        if item.source not in existing.source:
                            existing.source = f"{existing.source}; {item.source}"
                    elif item.source and item.source not in existing.source:
                        existing.source = f"{existing.source}; {item.source}"
                    existing.already_in_keyring = existing.already_in_keyring or item.already_in_keyring
                    existing.keyring_has_secret = existing.keyring_has_secret or item.keyring_has_secret
                else:
                    found[fp] = item

        after = self.keyring_fingerprints()
        unchanged = before == after
        items = sorted(found.values(), key=lambda k: (k.name or "", k.email or "", k.fingerprint))
        msg = (
            f"Varredura concluída (somente leitura).\n"
            f"{len(items)} chave(s) identificada(s).\n"
            f"Keyring inalterado: {'sim' if unchanged else 'não'}"
        )
        logger.info(
            "operação=discover_keys concluída count=%s keyring_unchanged=%s",
            len(items),
            unchanged,
        )
        return OpResult(
            ok=unchanged,
            message=msg,
            discovered=items,
            fingerprints=[i.fingerprint_normalized for i in items],
            status="discover",
        )

    def export_secret_protected(
        self,
        fingerprint: str,
        passphrase: Optional[str] = None,
    ) -> OpResult:
        """
        Backup privado protegido: exporta via GnuPG e cifra com a própria chave pública.
        Restauração exige a chave privada correspondente (+ passphrase do agente).
        """
        fp = normalize_fingerprint(fingerprint)
        logger.info("operação=export_secret_protected fp=%s", fp)
        secret = self.export_secret(fp, passphrase=passphrase)
        if not secret.ok or not secret.data:
            return OpResult(
                ok=False,
                message=secret.message or "Falha ao exportar material privado para proteção.",
                stderr=secret.stderr,
            )
        try:
            enc = self.gpg.encrypt(
                secret.data,
                recipients=[fp],
                always_trust=True,
                armor=True,
                passphrase=passphrase,
            )
        finally:
            # Não manter material privado em memória do OpResult intermediário
            secret.data = ""

        data = _to_text(getattr(enc, "data", None))
        ok = bool(getattr(enc, "ok", False)) and "BEGIN PGP MESSAGE" in data
        if "PRIVATE KEY BLOCK" in data:
            data = ""
            ok = False
        return OpResult(
            ok=ok,
            data=data if ok else "",
            fingerprints=[fp],
            status="export secret protected",
            message=(
                "Backup privado protegido criado pelo GnuPG.\n\n"
                "O ficheiro está cifrado para a sua própria chave pública.\n"
                "Para restaurar: importe/descriptografe com a chave privada correspondente."
                if ok
                else humanize_gpg_error(str(getattr(enc, "stderr", "") or ""), "encrypt backup failed")
            ),
            stderr="" if ok else str(getattr(enc, "stderr", "") or "encrypt failed"),
        )

    def save_export_file(
        self,
        fingerprint: str,
        path: str | Path,
        *,
        secret: bool = False,
        protected: bool = False,
        passphrase: Optional[str] = None,
    ) -> OpResult:
        """Exporta via GnuPG, grava com 0600 e valida fingerprint (sem logar conteúdo)."""
        fp = normalize_fingerprint(fingerprint)
        if secret and protected:
            result = self.export_secret_protected(fp, passphrase=passphrase)
            kind = "Backup privado protegido"
        elif secret:
            result = self.export_secret(fp, passphrase=passphrase)
            kind = "Backup da chave privada"
        else:
            result = self.export_public(fp)
            kind = "Chave pública"
        if not result.ok or not result.data:
            return result

        try:
            target = write_secure_file(path, result.data)
        except OSError as exc:
            result.data = ""
            return OpResult(ok=False, message=f"Falha ao gravar ficheiro.\n{exc}", fingerprints=[fp])
        finally:
            # Limpar material sensível da memória do resultado intermediário
            if secret:
                result.data = ""

        size = target.stat().st_size if target.is_file() else 0
        if size <= 0:
            return OpResult(ok=False, message="O ficheiro gravado está vazio.", fingerprints=[fp])

        if secret and protected:
            try:
                sample = target.read_bytes()[:120]
            except OSError as exc:
                return OpResult(ok=False, message=str(exc), fingerprints=[fp])
            if b"BEGIN PGP MESSAGE" not in sample:
                return OpResult(
                    ok=False,
                    message="Backup protegido inválido: esperado um MESSAGE cifrado pelo GnuPG.",
                    fingerprints=[fp],
                )
        else:
            verify = self.verify_exported_file(
                target,
                expected_fingerprint=fp,
                expect_secret=secret,
            )
            if not verify.ok:
                return OpResult(
                    ok=False,
                    message=f"Ficheiro gravado, mas a verificação falhou.\n{verify.message}",
                    fingerprints=[fp],
                    technical=str(target),
                )

        if secret:
            message = (
                f"{kind} criado.\n\n"
                f"Fingerprint:\n{format_fingerprint(fp)}\n\n"
                f"Arquivo:\n{target}\n\n"
                f"Tamanho: {size} bytes\n\n"
                "Proteja este ficheiro. Não o envie por canais não confiáveis."
            )
            panel_data = ""
        else:
            message = (
                f"Exportação concluída.\n\n"
                f"Fingerprint:\n{format_fingerprint(fp)}\n\n"
                f"Arquivo:\n{target}\n\n"
                f"Tipo:\n{kind}\n\n"
                f"Tamanho: {size} bytes"
            )
            panel_data = self.export_public(fp).data
        mode = oct(target.stat().st_mode & 0o777)
        logger.info(
            "operação=save_export_file kind=%s fp=%s size=%s mode=%s",
            "secret" if secret else "public",
            fp,
            size,
            mode,
        )
        return OpResult(
            ok=True,
            message=message,
            fingerprints=[fp],
            status=str(target),
            data=panel_data,
        )

    def verify_exported_file(
        self,
        path: str | Path,
        *,
        expected_fingerprint: str,
        expect_secret: bool = False,
    ) -> OpResult:
        """Valida ficheiro exportado: existe, tamanho > 0, GPG lê, fingerprint coincide."""
        target = Path(path)
        fp = normalize_fingerprint(expected_fingerprint)
        if not target.is_file():
            return OpResult(ok=False, message="O ficheiro exportado não existe.")
        try:
            size = target.stat().st_size
        except OSError as exc:
            return OpResult(ok=False, message=f"Não foi possível ler o ficheiro.\n{exc}")
        if size <= 0:
            return OpResult(ok=False, message="O ficheiro exportado está vazio.")

        if expect_secret:
            # Para backup privado: confirmar marcador sem logar conteúdo
            try:
                head = target.read_bytes()[:80]
            except OSError as exc:
                return OpResult(ok=False, message=str(exc))
            if b"PRIVATE KEY BLOCK" not in head and b"PRIVATE KEY" not in head:
                # armored files have header later — use inspect
                pass
            keys = self.inspect_key_file(target)
            if not keys:
                return OpResult(ok=False, message="O GnuPG não reconheceu chaves no backup.")
            match = next((k for k in keys if k.fingerprint_normalized == fp), None)
            if not match:
                return OpResult(
                    ok=False,
                    message="O fingerprint do ficheiro não corresponde à chave selecionada.",
                    fingerprints=[k.fingerprint_normalized for k in keys],
                )
            if not match.has_private:
                return OpResult(ok=False, message="O ficheiro não contém material privado.")
            return OpResult(ok=True, fingerprints=[fp], message="Backup privado verificado.")

        keys = self.inspect_key_file(target)
        if not keys:
            return OpResult(ok=False, message="O GnuPG não reconheceu chaves no ficheiro.")
        match = next((k for k in keys if k.fingerprint_normalized == fp), None)
        if not match:
            return OpResult(
                ok=False,
                message="O fingerprint do ficheiro não corresponde à chave selecionada.",
                fingerprints=[k.fingerprint_normalized for k in keys],
            )
        if match.has_private:
            return OpResult(
                ok=False,
                message="Recusa de segurança: a exportação pública contém material privado.",
            )
        return OpResult(ok=True, fingerprints=[fp], message="Exportação pública verificada.")

    # ---------- operações de mensagem ----------

    def encrypt(
        self,
        message: str,
        recipients: list[str],
        sign_key: Optional[str] = None,
        passphrase: Optional[str] = None,
        always_trust: bool = True,
    ) -> OpResult:
        fps = [normalize_fingerprint(r) for r in recipients]
        if not fps:
            return OpResult(ok=False, message="Nenhum destinatário selecionado.")
        logger.info(
            "operação=encrypt recipients=%s sign=%s",
            fps,
            normalize_fingerprint(sign_key) if sign_key else None,
        )
        kwargs: dict = {
            "recipients": fps,
            "armor": True,
            "always_trust": always_trust,
        }
        if sign_key:
            kwargs["sign"] = normalize_fingerprint(sign_key)
            if passphrase is not None:
                kwargs["passphrase"] = passphrase
        enc = self.gpg.encrypt(message, **kwargs)
        ok = bool(enc.ok)
        logger.info("operação=encrypt concluída ok=%s status=%s", ok, enc.status)
        return OpResult(
            ok=ok,
            data=_to_text(enc.data) if ok else "",
            status=str(enc.status or ""),
            stderr=_to_text(enc.stderr),
            fingerprints=fps,
            message="Mensagem criptografada." if ok else humanize_gpg_error(_to_text(enc.stderr), str(enc.status or "")),
            technical=_to_text(enc.stderr),
        )

    def decrypt(self, ciphertext: str, passphrase: Optional[str] = None) -> OpResult:
        logger.info("operação=decrypt início")
        raw = _to_text(ciphertext)
        if armor_looks_incomplete(raw):
            return OpResult(
                ok=False,
                data="",
                status="incomplete armor",
                stderr="",
                message=(
                    "O bloco OpenPGP está incompleto (falta a linha -----END PGP…-----).\n"
                    "Cole a mensagem inteira, do BEGIN ao END."
                ),
                technical=raw[:200],
            )
        cleaned = normalize_pgp_input(raw)
        kwargs = {}
        if passphrase is not None:
            kwargs["passphrase"] = passphrase
        payload = cleaned.encode("utf-8")
        dec = self.gpg.decrypt(payload, **kwargs)
        ok = bool(dec.ok)
        fp = normalize_fingerprint(getattr(dec, "fingerprint", "") or "")
        logger.info("operação=decrypt concluída ok=%s", ok)
        return OpResult(
            ok=ok,
            data=_to_text(dec.data) if ok else "",
            status=str(dec.status or ""),
            stderr=_to_text(dec.stderr),
            username=str(dec.username or ""),
            fingerprints=[fp] if fp else [],
            valid=bool(getattr(dec, "valid", False)),
            message="Mensagem descriptografada." if ok else humanize_gpg_error(_to_text(dec.stderr), str(dec.status or "")),
            technical=_to_text(dec.stderr),
        )

    def sign(
        self,
        message: str,
        keyid: str,
        clearsign: bool = True,
        detach: bool = False,
        passphrase: Optional[str] = None,
    ) -> OpResult:
        fp = normalize_fingerprint(keyid)
        logger.info("operação=sign fp=%s clearsign=%s detach=%s", fp, clearsign, detach)
        kwargs = {
            "keyid": fp,
            "clearsign": clearsign,
            "detach": detach,
            "binary": False,
        }
        if passphrase is not None:
            kwargs["passphrase"] = passphrase
        signed = self.gpg.sign(message, **kwargs)
        data = _to_text(signed.data)
        ok = bool(data) and bool(getattr(signed, "fingerprint", None) or "BEGIN PGP" in data)
        logger.info("operação=sign concluída ok=%s", ok)
        return OpResult(
            ok=ok,
            data=data,
            status=str(signed.status or ""),
            stderr=_to_text(signed.stderr),
            fingerprints=[normalize_fingerprint(signed.fingerprint)] if getattr(signed, "fingerprint", None) else [fp],
            message="Mensagem assinada." if ok else humanize_gpg_error(_to_text(signed.stderr), str(signed.status or "")),
            technical=_to_text(signed.stderr),
        )

    def verify(self, data: str, signature: Optional[str] = None) -> OpResult:
        logger.info("operação=verify detach=%s", bool(signature))
        data = normalize_pgp_input(data)
        if signature:
            signature = normalize_pgp_input(signature)
        tmp_path = None
        try:
            if signature:
                fd, tmp_path = tempfile.mkstemp(prefix="pgpdesk-sig-", suffix=".asc")
                os.close(fd)
                os.chmod(tmp_path, 0o600)
                with open(tmp_path, "w", encoding="utf-8") as fh:
                    fh.write(signature)
                verified = self.gpg.verify_data(tmp_path, data.encode("utf-8"))
            else:
                verified = self.gpg.verify(data.encode("utf-8"))
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        valid = getattr(verified, "valid", None)
        fp = normalize_fingerprint(getattr(verified, "fingerprint", "") or "")
        username = str(getattr(verified, "username", "") or "")
        name, email = parse_uid(username)
        status = str(getattr(verified, "status", "") or "")
        stderr = str(getattr(verified, "stderr", "") or "")

        if valid is True:
            message = (
                "✓ Assinatura criptograficamente válida\n\n"
                f"Assinante:\nNome: {name or '(não informado)'}\n"
                f"E-mail: {email or '(não informado)'}\n\n"
                f"Fingerprint:\n{format_fingerprint(fp) if fp else '(indisponível)'}\n\n"
                "A validade criptográfica da assinatura não comprova, por si só,\n"
                "que a identidade do assinante foi confirmada por você."
            )
            ok = True
        elif valid is False:
            message = "✗ Assinatura inválida"
            ok = False
        else:
            message = "⚠ Não foi possível determinar a validade da assinatura"
            ok = False

        logger.info("operação=verify concluída valid=%s fp=%s", valid, fp)
        return OpResult(
            ok=ok,
            data=message,
            status=status,
            stderr=stderr,
            username=username,
            fingerprints=[fp] if fp else [],
            valid=valid if isinstance(valid, bool) else None,
            message=message,
            technical=stderr,
        )

    # ---------- ficheiros ----------

    def encrypt_file(
        self,
        path: str,
        recipients: list[str],
        output: str,
        sign_key: Optional[str] = None,
        passphrase: Optional[str] = None,
        always_trust: bool = True,
    ) -> OpResult:
        fps = [normalize_fingerprint(r) for r in recipients]
        logger.info("operação=encrypt_file recipients=%s", fps)
        kwargs: dict = {
            "recipients": fps,
            "output": output,
            "armor": True,
            "always_trust": always_trust,
        }
        if sign_key:
            kwargs["sign"] = normalize_fingerprint(sign_key)
            if passphrase is not None:
                kwargs["passphrase"] = passphrase
        with open(path, "rb") as fh:
            enc = self.gpg.encrypt_file(fh, **kwargs)
        ok = bool(enc.ok)
        if ok:
            try:
                os.chmod(output, 0o600)
            except OSError:
                pass
        return OpResult(
            ok=ok,
            data=output if ok else "",
            status=str(enc.status or ""),
            stderr=str(enc.stderr or ""),
            fingerprints=fps,
            message="Ficheiro criptografado." if ok else humanize_gpg_error(str(enc.stderr or ""), str(enc.status or "")),
            technical=str(enc.stderr or ""),
        )

    def decrypt_file(
        self,
        path: str,
        output: str,
        passphrase: Optional[str] = None,
    ) -> OpResult:
        logger.info("operação=decrypt_file")
        kwargs = {"output": output}
        if passphrase is not None:
            kwargs["passphrase"] = passphrase
        with open(path, "rb") as fh:
            dec = self.gpg.decrypt_file(fh, **kwargs)
        ok = bool(dec.ok)
        if ok:
            try:
                os.chmod(output, 0o600)
            except OSError:
                pass
        return OpResult(
            ok=ok,
            data=output if ok else "",
            status=str(dec.status or ""),
            stderr=str(dec.stderr or ""),
            username=str(dec.username or ""),
            valid=bool(getattr(dec, "valid", False)),
            message="Ficheiro descriptografado." if ok else humanize_gpg_error(str(dec.stderr or ""), str(dec.status or "")),
            technical=str(dec.stderr or ""),
        )

    def sign_file(
        self,
        path: str,
        output: str,
        keyid: str,
        clearsign: bool = False,
        detach: bool = True,
        passphrase: Optional[str] = None,
    ) -> OpResult:
        fp = normalize_fingerprint(keyid)
        logger.info("operação=sign_file fp=%s", fp)
        kwargs = {
            "keyid": fp,
            "clearsign": clearsign,
            "detach": detach,
            "output": output,
            "binary": False,
        }
        if passphrase is not None:
            kwargs["passphrase"] = passphrase
        with open(path, "rb") as fh:
            signed = self.gpg.sign_file(fh, **kwargs)
        data_ok = bool(getattr(signed, "fingerprint", None)) or (
            Path(output).is_file() and Path(output).stat().st_size > 0
        )
        if data_ok:
            try:
                os.chmod(output, 0o600)
            except OSError:
                pass
        return OpResult(
            ok=bool(data_ok),
            data=output if data_ok else "",
            status=str(getattr(signed, "status", "") or ""),
            stderr=str(getattr(signed, "stderr", "") or ""),
            fingerprints=[fp],
            message="Ficheiro assinado." if data_ok else humanize_gpg_error(str(getattr(signed, "stderr", "") or "")),
            technical=str(getattr(signed, "stderr", "") or ""),
        )

    def verify_file(self, path: str, signature_path: Optional[str] = None) -> OpResult:
        logger.info("operação=verify_file detach=%s", bool(signature_path))
        if signature_path:
            with open(path, "rb") as fh:
                verified = self.gpg.verify_file(fh, signature_path)
        else:
            with open(path, "rb") as fh:
                verified = self.gpg.verify_file(fh)
        # Reutiliza formatação humana via verify textual quando possível
        valid = getattr(verified, "valid", None)
        fp = normalize_fingerprint(getattr(verified, "fingerprint", "") or "")
        username = str(getattr(verified, "username", "") or "")
        name, email = parse_uid(username)
        if valid is True:
            message = (
                "✓ Assinatura criptograficamente válida\n\n"
                f"Assinante:\nNome: {name or '(não informado)'}\n"
                f"E-mail: {email or '(não informado)'}\n\n"
                f"Fingerprint:\n{format_fingerprint(fp) if fp else '(indisponível)'}\n\n"
                "A validade criptográfica da assinatura não comprova, por si só,\n"
                "que a identidade do assinante foi confirmada por você."
            )
            ok = True
        elif valid is False:
            message = "✗ Assinatura inválida"
            ok = False
        else:
            message = "⚠ Não foi possível determinar a validade da assinatura"
            ok = False
        return OpResult(
            ok=ok,
            data=message,
            status=str(getattr(verified, "status", "") or ""),
            stderr=str(getattr(verified, "stderr", "") or ""),
            username=username,
            fingerprints=[fp] if fp else [],
            valid=valid if isinstance(valid, bool) else None,
            message=message,
            technical=str(getattr(verified, "stderr", "") or ""),
        )
