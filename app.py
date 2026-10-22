#!/usr/bin/env python3
"""PGP Desk — aplicação gráfica local sobre GnuPG / gpg-agent."""

from __future__ import annotations

import logging
import os
import stat
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Optional

from gpg_service import (
    DiscoveredKey,
    GpgService,
    KeyInfo,
    OpResult,
    format_fingerprint,
    normalize_fingerprint,
)

APP_TITLE = "PGP Desk"
APP_MIN_W = 880
APP_MIN_H = 600
APP_MARGIN = 48  # folga em relação ao ecrã disponível

# Paleta: tinta-petróleo + latão (selo / confiança criptográfica)
COLOR = {
    "bg": "#0E1F24",
    "surface": "#163038",
    "raised": "#1E3D47",
    "border": "#2A4F5A",
    "fg": "#E6F1F0",
    "muted": "#7A9A9E",
    "accent": "#C4A35A",
    "accent_active": "#D4B86A",
    "accent_fg": "#0E1F24",
    "danger": "#C46B5A",
    "status": "#0A171B",
    "text_bg": "#12282E",
    "select": "#2F5A48",
}


def _pick_font(preferred: tuple[str, ...], fallback: str) -> str:
    try:
        import tkinter.font as tkfont

        available = set(tkfont.families())
        for name in preferred:
            if name in available:
                return name
    except Exception:
        pass
    return fallback


def fit_window(
    win: tk.Misc,
    *,
    min_w: int = APP_MIN_W,
    min_h: int = APP_MIN_H,
    max_w: Optional[int] = None,
    max_h: Optional[int] = None,
    prefer_w: Optional[int] = None,
    prefer_h: Optional[int] = None,
    grow_only: bool = False,
    center: bool = False,
) -> None:
    """Ajusta geometria ao conteúdo pedido, limitada ao ecrã disponível."""
    try:
        win.update_idletasks()
    except tk.TclError:
        return

    req_w = max(int(win.winfo_reqwidth()), prefer_w or 0, min_w)
    req_h = max(int(win.winfo_reqheight()), prefer_h or 0, min_h)

    screen_w = int(win.winfo_screenwidth())
    screen_h = int(win.winfo_screenheight())
    avail_w = max(min_w, screen_w - APP_MARGIN)
    avail_h = max(min_h, screen_h - APP_MARGIN)

    if max_w is not None:
        avail_w = min(avail_w, max_w)
    if max_h is not None:
        avail_h = min(avail_h, max_h)

    width = min(req_w, avail_w)
    height = min(req_h, avail_h)

    if grow_only:
        try:
            cur_w = max(int(win.winfo_width()), min_w)
            cur_h = max(int(win.winfo_height()), min_h)
            # winfo_* pode ser 1 antes do mapear
            if cur_w > 1:
                width = max(width, cur_w)
            if cur_h > 1:
                height = max(height, cur_h)
            width = min(width, avail_w)
            height = min(height, avail_h)
        except tk.TclError:
            pass

    try:
        win.minsize(min_w, min_h)
    except tk.TclError:
        pass

    setattr(win, "_fitting_geometry", True)
    try:
        if center:
            x = max(0, (screen_w - width) // 2)
            y = max(0, (screen_h - height) // 2)
            win.geometry(f"{width}x{height}+{x}+{y}")
        else:
            win.geometry(f"{width}x{height}")
        try:
            win.update_idletasks()
        except tk.TclError:
            pass
    finally:
        setattr(win, "_fitting_geometry", False)


def _project_root() -> Path:
    """Raiz do projeto (fonte) ou pasta do executável empacotado."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent.parent
    return Path(__file__).resolve().parent


def _bundle_root() -> Path:
    """Recursos embutidos no PyInstaller (ícones etc.)."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent


PROJECT_ROOT = _project_root()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("pgp_desk.app")


def ensure_secrets_layout(root: Path = PROJECT_ROOT) -> None:
    """Cria secrets/{public,backup} com permissões restritas (sem copiar chaves)."""
    secrets = root / "secrets"
    public = secrets / "public"
    backup = secrets / "backup"
    for path in (secrets, public, backup):
        path.mkdir(mode=0o700, exist_ok=True)
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass
    for path in secrets.rglob("*"):
        if path.is_file():
            try:
                mode = path.stat().st_mode
                if mode & (stat.S_IRWXG | stat.S_IRWXO):
                    os.chmod(path, 0o600)
            except OSError:
                pass


class TextPanel(ttk.Frame):
    """Painel de texto com Colar/Copiar/Limpar/Abrir/Salvar."""

    def __init__(self, master, title: str, height: int = 12, *, sensitive: bool = False, **kwargs):
        super().__init__(master, **kwargs)
        self.sensitive = sensitive
        head = ttk.Frame(self)
        head.pack(fill="x")
        ttk.Label(head, text=title, style="Heading.TLabel").pack(side="left")
        btns = ttk.Frame(head)
        btns.pack(side="right")
        ttk.Button(btns, text="Colar", width=8, command=self.paste).pack(side="left", padx=2)
        ttk.Button(btns, text="Copiar", width=8, command=self.copy).pack(side="left", padx=2)
        ttk.Button(btns, text="Limpar", width=8, command=self.clear).pack(side="left", padx=2)
        ttk.Button(btns, text="Abrir…", width=8, command=self.load_file).pack(side="left", padx=2)
        ttk.Button(btns, text="Salvar…", width=8, command=self.save_file).pack(side="left", padx=2)

        wrap = ttk.Frame(self, style="Inset.TFrame")
        wrap.pack(fill="both", expand=True, pady=(6, 0))
        mono_family = _pick_font(("DejaVu Sans Mono", "Noto Mono", "Liberation Mono"), "Courier")
        self.text = tk.Text(
            wrap,
            height=height,
            wrap="word",
            font=(mono_family, 10),
            undo=True,
            relief="flat",
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=COLOR["border"],
            highlightcolor=COLOR["accent"],
            background=COLOR["text_bg"],
            foreground=COLOR["fg"],
            insertbackground=COLOR["accent"],
            selectbackground=COLOR["select"],
            selectforeground=COLOR["fg"],
            padx=10,
            pady=10,
        )
        scroll = ttk.Scrollbar(wrap, command=self.text.yview)
        self.text.configure(yscrollcommand=scroll.set)
        self.text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def get(self) -> str:
        return self.text.get("1.0", "end-1c")

    def set(self, value: str) -> None:
        self.text.delete("1.0", "end")
        self.text.insert("1.0", value)

    def clear(self) -> None:
        self.set("")

    def copy(self) -> None:
        data = self.get()
        if not data:
            return
        self.clipboard_clear()
        self.clipboard_append(data)
        if self.sensitive or "PRIVATE KEY BLOCK" in data:
            messagebox.showwarning(
                APP_TITLE,
                "O conteúdo foi colocado no clipboard do sistema.\n"
                "Trate-o como sensível e limpe o clipboard quando terminar.",
            )

    def paste(self) -> None:
        try:
            data = self.clipboard_get()
        except tk.TclError:
            return
        self.text.insert("insert", data)

    def load_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Abrir ficheiro",
            filetypes=[("Texto / PGP", "*.txt *.asc *.pgp *.gpg *.sig"), ("Todos", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                self.set(fh.read())
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Erro ao abrir o ficheiro.\n{exc}")

    def save_file(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Salvar",
            defaultextension=".asc",
            filetypes=[("ASCII armored", "*.asc"), ("Texto", "*.txt"), ("Todos", "*.*")],
        )
        if not path:
            return
        if not confirm_overwrite(path):
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.get())
            os.chmod(path, 0o600)
            messagebox.showinfo(APP_TITLE, f"Salvo em:\n{path}")
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Erro ao salvar.\n{exc}")


def confirm_overwrite(path: str) -> bool:
    if not path or not os.path.exists(path):
        return True
    return messagebox.askyesno(
        APP_TITLE,
        "O arquivo já existe.\n\nDeseja substituí-lo?",
        icon="warning",
    )


class RecipientPicker(ttk.LabelFrame):
    """Seleção múltipla de destinatários por fingerprint completo."""

    def __init__(self, master, title: str = "Destinatários (chaves públicas)", **kwargs):
        super().__init__(master, text=title, padding=8, **kwargs)
        self._keys: list[KeyInfo] = []
        self._vars: dict[str, tk.BooleanVar] = {}
        canvas = tk.Canvas(
            self,
            height=110,
            highlightthickness=1,
            highlightbackground=COLOR["border"],
            background=COLOR["text_bg"],
            borderwidth=0,
        )
        scroll = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.inner = ttk.Frame(canvas, style="Inset.TFrame")
        self.inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.inner, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self._canvas = canvas

    def set_keys(self, keys: list[KeyInfo]) -> None:
        previous = {fp for fp, var in self._vars.items() if var.get()}
        for child in self.inner.winfo_children():
            child.destroy()
        self._keys = keys
        self._vars = {}
        for key in keys:
            var = tk.BooleanVar(value=key.fingerprint_normalized in previous)
            self._vars[key.fingerprint_normalized] = var
            text = (
                f"{key.name or '(sem nome)'}  |  {key.email or '(sem e-mail)'}\n"
                f"{key.fingerprint_display}"
            )
            ttk.Checkbutton(self.inner, text=text, variable=var).pack(anchor="w", pady=2, fill="x")

    def selected(self) -> list[KeyInfo]:
        selected = []
        for key in self._keys:
            var = self._vars.get(key.fingerprint_normalized)
            if var is not None and var.get():
                selected.append(key)
        return selected


class PgpApp(tk.Tk):
    def __init__(self) -> None:
        # WM_CLASS = "pgpdesk", "PgpDesk" — GNOME usa StartupWMClass p/ ícone na barra
        super().__init__(className="PgpDesk")
        self.title(APP_TITLE)
        self.minsize(APP_MIN_W, APP_MIN_H)
        self._user_resized = False
        self._set_window_icon()

        ensure_secrets_layout()

        try:
            self.service = GpgService(use_loopback=False)
        except FileNotFoundError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            raise SystemExit(1) from exc

        self.pub_keys: list[KeyInfo] = []
        self.sec_keys: list[KeyInfo] = []
        self._signer_combos: list[ttk.Combobox] = []

        self._setup_style()
        self._build()
        self._run_startup_checks()
        self.refresh_keys()
        self._fit_main_window(initial=True)
        self.bind("<Configure>", self._on_user_configure, add="+")

    def _set_window_icon(self) -> None:
        """Define ícone da janela (_NET_WM_ICON) para a barra/dock."""
        roots = [
            _bundle_root() / "assets",
            PROJECT_ROOT / "assets",
            Path(__file__).resolve().parent / "assets",
        ]
        # Preferir tamanhos médios — 512px às vezes falha no PhotoImage/Tk
        names = ("pgp-desk-64.png", "pgp-desk-128.png", "pgp-desk-48.png", "pgp-desk.png")
        images: list[tk.PhotoImage] = []
        for root in roots:
            for name in names:
                path = root / name
                if not path.is_file():
                    continue
                try:
                    images.append(tk.PhotoImage(file=str(path)))
                except tk.TclError:
                    continue
            if images:
                break
        if not images:
            return
        self._icon_images = images  # manter referência
        try:
            self.iconphoto(True, *images)
        except tk.TclError:
            try:
                self.iconphoto(True, images[0])
            except tk.TclError:
                pass

    def _setup_style(self) -> None:
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")

        bg = COLOR["bg"]
        surface = COLOR["surface"]
        raised = COLOR["raised"]
        border = COLOR["border"]
        fg = COLOR["fg"]
        muted = COLOR["muted"]
        accent = COLOR["accent"]
        accent_active = COLOR["accent_active"]
        accent_fg = COLOR["accent_fg"]

        self.ui_font = _pick_font(("Noto Sans", "DejaVu Sans", "Liberation Sans"), "TkDefaultFont")
        self.mono_font = _pick_font(("DejaVu Sans Mono", "Noto Mono", "Liberation Mono"), "Courier")

        self.configure(bg=bg)
        style.configure(
            ".",
            background=bg,
            foreground=fg,
            fieldbackground=surface,
            bordercolor=border,
            darkcolor=bg,
            lightcolor=raised,
            troughcolor=surface,
            focuscolor=accent,
            font=(self.ui_font, 10),
        )
        style.configure("TFrame", background=bg)
        style.configure("Header.TFrame", background=bg)
        style.configure("Inset.TFrame", background=COLOR["text_bg"])
        style.configure("TLabel", background=bg, foreground=fg, font=(self.ui_font, 10))
        style.configure("Brand.TLabel", background=bg, foreground=fg, font=(self.ui_font, 20, "bold"))
        style.configure("Heading.TLabel", background=bg, foreground=fg, font=(self.ui_font, 10, "bold"))
        style.configure("Muted.TLabel", background=bg, foreground=muted, font=(self.ui_font, 9))
        style.configure("Fingerprint.TLabel", background=bg, foreground=accent, font=(self.mono_font, 9))
        style.configure("TButton", padding=(12, 7), background=raised, foreground=fg, bordercolor=border)
        style.map(
            "TButton",
            background=[("active", surface), ("pressed", COLOR["select"])],
            foreground=[("disabled", muted)],
        )
        style.configure(
            "Accent.TButton",
            background=accent,
            foreground=accent_fg,
            bordercolor=accent,
            font=(self.ui_font, 10, "bold"),
            padding=(14, 8),
        )
        style.map(
            "Accent.TButton",
            background=[("active", accent_active), ("pressed", "#B8944A")],
            foreground=[("disabled", muted)],
        )
        style.configure(
            "Ghost.TButton",
            background=bg,
            foreground=muted,
            bordercolor=border,
            padding=(10, 7),
        )
        style.map("Ghost.TButton", background=[("active", surface)], foreground=[("active", fg)])
        style.configure("TNotebook", background=bg, borderwidth=0, tabmargins=(0, 0, 0, 0))
        style.configure(
            "TNotebook.Tab",
            padding=(14, 9),
            background=surface,
            foreground=muted,
            font=(self.ui_font, 10),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", raised), ("active", raised)],
            foreground=[("selected", fg), ("active", fg)],
        )
        style.configure("TLabelframe", background=bg, foreground=fg, bordercolor=border)
        style.configure(
            "TLabelframe.Label",
            background=bg,
            foreground=muted,
            font=(self.ui_font, 9, "bold"),
        )
        style.configure(
            "TCombobox",
            fieldbackground=surface,
            background=surface,
            foreground=fg,
            arrowcolor=accent,
            bordercolor=border,
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", surface)],
            selectbackground=[("readonly", COLOR["select"])],
            selectforeground=[("readonly", fg)],
        )
        style.configure(
            "Treeview",
            background=COLOR["text_bg"],
            fieldbackground=COLOR["text_bg"],
            foreground=fg,
            rowheight=30,
            bordercolor=border,
            font=(self.ui_font, 9),
        )
        style.configure(
            "Treeview.Heading",
            background=raised,
            foreground=muted,
            font=(self.ui_font, 9, "bold"),
            bordercolor=border,
        )
        style.map(
            "Treeview",
            background=[("selected", COLOR["select"])],
            foreground=[("selected", fg)],
        )
        style.configure("TEntry", fieldbackground=surface, foreground=fg, insertcolor=accent, bordercolor=border)
        style.configure("TCheckbutton", background=COLOR["text_bg"], foreground=fg, font=(self.ui_font, 9))
        style.map("TCheckbutton", background=[("active", COLOR["text_bg"])])
        style.configure("TRadiobutton", background=bg, foreground=fg)
        style.map("TRadiobutton", background=[("active", bg)])
        style.configure(
            "Status.TLabel",
            background=COLOR["status"],
            foreground=muted,
            padding=(14, 10),
            font=(self.ui_font, 9),
        )
        style.configure(
            "Vertical.TScrollbar",
            background=raised,
            troughcolor=COLOR["text_bg"],
            bordercolor=border,
            arrowcolor=muted,
        )
        style.configure(
            "Horizontal.TScrollbar",
            background=raised,
            troughcolor=COLOR["text_bg"],
            bordercolor=border,
            arrowcolor=muted,
        )

    def _build(self) -> None:
        top = ttk.Frame(self, style="Header.TFrame", padding=(16, 14, 16, 10))
        top.pack(fill="x")

        brand = ttk.Frame(top, style="Header.TFrame")
        brand.pack(side="left", fill="x", expand=True)
        ttk.Label(brand, text="PGP Desk", style="Brand.TLabel").pack(anchor="w")
        ttk.Label(
            brand,
            text="GnuPG local · gpg-agent · sem armazenamento de passphrase",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(2, 0))
        self.header_fp = tk.StringVar(value="")
        ttk.Label(brand, textvariable=self.header_fp, style="Fingerprint.TLabel").pack(anchor="w", pady=(4, 0))

        actions = ttk.Frame(top, style="Header.TFrame")
        actions.pack(side="right")
        ttk.Button(
            actions,
            text="Copiar chave pública",
            style="Accent.TButton",
            command=self.do_copy_public_key,
        ).pack(side="left", padx=(0, 6))
        ttk.Button(actions, text="Atualizar chaves", style="Ghost.TButton", command=self.refresh_keys).pack(
            side="left", padx=2
        )
        ttk.Button(actions, text="Diagnóstico", style="Ghost.TButton", command=self.show_diagnostics).pack(
            side="left", padx=2
        )

        rule = tk.Frame(self, height=2, bg=COLOR["accent"], borderwidth=0, highlightthickness=0)
        rule.pack(fill="x", padx=16, pady=(0, 8))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        self._tab_encrypt()
        self._tab_decrypt()
        self._tab_sign()
        self._tab_verify()
        self._tab_sign_encrypt()
        self._tab_files()
        self._tab_keys()
        self._keys_tab_index = self.notebook.index("end") - 1

        self.status = tk.StringVar(value="")
        ttk.Label(self, textvariable=self.status, style="Status.TLabel", anchor="w").pack(fill="x", side="bottom")

    def _run_startup_checks(self) -> None:
        env = self.service.check_gpg_environment()
        if not env.ok:
            messagebox.showerror(
                APP_TITLE,
                "Falha na verificação do ambiente GnuPG.\n\n" + "\n".join(env.details),
            )
        self.set_status(
            f"{env.version or 'GnuPG'} · home={env.gnupg_home} · "
            f"pub={env.public_count} priv={env.secret_count}"
        )

    # ---------- UI helpers ----------

    def set_status(self, msg: str, ok: Optional[bool] = None) -> None:
        prefix = "✓ " if ok is True else "✗ " if ok is False else ""
        self.status.set(prefix + msg)

    def show_result(self, result: OpResult, success_msg: str = "") -> None:
        if result.ok:
            self.set_status(success_msg or result.user_message(), True)
            msg = success_msg or result.user_message()
            if result.message and result.message != msg:
                msg = f"{msg}\n\n{result.message}"
            messagebox.showinfo(APP_TITLE, msg)
        else:
            self.set_status(result.user_message(), False)
            detail = result.user_message()
            if result.technical:
                detail += f"\n\nDetalhe técnico:\n{result.technical[:400]}"
            messagebox.showerror(APP_TITLE, detail)

    def _signer_combo(self, parent, label: str, row: int) -> ttk.Combobox:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="nw", pady=4, padx=(0, 8))
        combo = ttk.Combobox(parent, state="readonly", width=78)
        combo.grid(row=row, column=1, sticky="ew", pady=4)
        self._signer_combos.append(combo)
        return combo

    def _selected_signer(self, combo: ttk.Combobox) -> Optional[KeyInfo]:
        label = combo.get()
        for key in self.sec_keys:
            if key.label == label:
                return key
        return None

    def refresh_keys(self) -> None:
        try:
            self.pub_keys = self.service.list_public_keys()
            self.sec_keys = self.service.list_secret_keys()
        except Exception as exc:  # noqa: BLE001
            logger.exception("falha ao listar chaves")
            messagebox.showerror(APP_TITLE, f"Erro ao listar chaves.\n{exc}")
            return

        sec_labels = [k.label for k in self.sec_keys]
        for combo in self._signer_combos:
            current = combo.get()
            combo["values"] = sec_labels
            if current in sec_labels:
                combo.set(current)
            elif sec_labels:
                combo.current(0)
            else:
                combo.set("")

        for picker in (
            getattr(self, "enc_recipients", None),
            getattr(self, "se_recipients", None),
            getattr(self, "file_enc_recipients", None),
            getattr(self, "file_se_recipients", None),
        ):
            if picker is not None:
                picker.set_keys(self.pub_keys)

        self._reload_key_trees()
        self._update_header_identity()
        self._adapt_lists_to_items()
        self.set_status(
            f"{len(self.pub_keys)} pública(s) · {len(self.sec_keys)} privada(s) · {self.service.gnupg_home}"
        )
        self._fit_main_window()

    def _on_user_configure(self, event: tk.Event) -> None:
        # Ignorar eventos gerados pelo próprio fit_window
        if event.widget is not self:
            return
        if getattr(self, "_fitting_geometry", False):
            return
        if getattr(self, "_fit_ready", False):
            self._user_resized = True

    def _adapt_lists_to_items(self) -> None:
        """Ajusta alturas de listas/painéis conforme quantidade de chaves."""
        n_keys = len({k.fingerprint_normalized for k in self.pub_keys + self.sec_keys})
        tree = getattr(self, "keys_tree", None)
        if tree is not None:
            # 4–14 linhas visíveis conforme o número de chaves
            tree.configure(height=max(4, min(14, max(n_keys, 4))))

        # Destinatários: canvas cresce um pouco com mais chaves
        canvas_h = max(90, min(220, 36 + n_keys * 34))
        for picker in (
            getattr(self, "enc_recipients", None),
            getattr(self, "se_recipients", None),
            getattr(self, "file_enc_recipients", None),
            getattr(self, "file_se_recipients", None),
        ):
            if picker is not None and hasattr(picker, "_canvas"):
                picker._canvas.configure(height=canvas_h)

    def _fit_main_window(self, *, initial: bool = False) -> None:
        if not initial and self._user_resized:
            return
        n_keys = len({k.fingerprint_normalized for k in self.pub_keys + self.sec_keys})
        # Base + espaço extra quando há mais chaves/listas
        prefer_h = 680 + min(200, max(0, n_keys - 2) * 28)
        fit_window(
            self,
            min_w=APP_MIN_W,
            min_h=APP_MIN_H,
            prefer_w=1080,
            prefer_h=prefer_h,
            grow_only=not initial,
            center=initial,
        )
        self._fit_ready = True

    def _update_header_identity(self) -> None:
        if not hasattr(self, "header_fp"):
            return
        key = self.sec_keys[0] if self.sec_keys else (self.pub_keys[0] if self.pub_keys else None)
        if key is None:
            self.header_fp.set("Nenhuma chave no keyring")
            return
        who = key.name or key.email or "Chave local"
        self.header_fp.set(f"{who}  ·  {key.fingerprint_display}")

    def confirm_recipients(self, recipients: list[KeyInfo], signer: Optional[KeyInfo] = None) -> bool:
        if not recipients:
            messagebox.showwarning(APP_TITLE, "Selecione pelo menos um destinatário.")
            return False
        blocks = []
        if signer:
            blocks.append(signer.identity_block("Assinatura"))
            blocks.append("")
        for i, key in enumerate(recipients, 1):
            title = "Destinatário" if len(recipients) == 1 else f"Destinatário {i}"
            blocks.append(key.identity_block(title))
            blocks.append("")
        blocks.append("O fingerprint é o identificador de confiança.\nContinuar?")
        return messagebox.askyesno(APP_TITLE, "\n".join(blocks))

    def confirm_signer(self, signer: KeyInfo) -> bool:
        return messagebox.askyesno(
            APP_TITLE,
            signer.identity_block("Chave de assinatura") + "\n\nAssinar com esta chave?",
        )

    # ---------- tabs ----------

    def _tab_encrypt(self) -> None:
        tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab, text="Criptografar")
        self.enc_recipients = RecipientPicker(tab)
        self.enc_recipients.pack(fill="x")
        self.enc_in = TextPanel(tab, "Mensagem em claro", height=9, sensitive=True)
        self.enc_in.pack(fill="both", expand=True, pady=8)
        ttk.Button(tab, text="Criptografar", style="Accent.TButton", command=self.do_encrypt).pack(anchor="e")
        self.enc_out = TextPanel(tab, "Resultado (criptografado)", height=9)
        self.enc_out.pack(fill="both", expand=True, pady=8)

    def _tab_decrypt(self) -> None:
        tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab, text="Descriptografar")
        ttk.Label(
            tab,
            text="Usa a chave privada do keyring (~/.gnupg). A autenticação é feita pelo gpg-agent/pinentry.",
            style="Muted.TLabel",
        ).pack(anchor="w")
        self.dec_in = TextPanel(tab, "Mensagem criptografada", height=12)
        self.dec_in.pack(fill="both", expand=True, pady=8)
        ttk.Button(tab, text="Descriptografar", style="Accent.TButton", command=self.do_decrypt).pack(anchor="e")
        self.dec_out = TextPanel(tab, "Mensagem em claro", height=10, sensitive=True)
        self.dec_out.pack(fill="both", expand=True, pady=8)

    def _tab_sign(self) -> None:
        tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab, text="Assinar")
        opts = ttk.Frame(tab)
        opts.pack(fill="x")
        opts.columnconfigure(1, weight=1)
        self.sign_key = self._signer_combo(opts, "Chave de assinatura (privada):", 0)
        self.sign_mode = tk.StringVar(value="clearsign")
        modes = ttk.Frame(opts)
        modes.grid(row=1, column=0, columnspan=2, sticky="w", pady=6)
        ttk.Label(modes, text="Modo:").pack(side="left", padx=(0, 8))
        for text, value in (
            ("Clearsign", "clearsign"),
            ("Embutida", "sign"),
            ("Destacada (detach)", "detach"),
        ):
            ttk.Radiobutton(modes, text=text, variable=self.sign_mode, value=value).pack(side="left", padx=4)
        self.sign_in = TextPanel(tab, "Mensagem a assinar", height=10, sensitive=True)
        self.sign_in.pack(fill="both", expand=True, pady=8)
        ttk.Button(tab, text="Assinar", style="Accent.TButton", command=self.do_sign).pack(anchor="e")
        self.sign_out = TextPanel(tab, "Resultado assinado", height=10)
        self.sign_out.pack(fill="both", expand=True, pady=8)

    def _tab_verify(self) -> None:
        tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab, text="Verificar")
        ttk.Label(
            tab,
            text="Validade criptográfica ≠ identidade confirmada. Confirme o fingerprint fora da banda.",
            style="Muted.TLabel",
        ).pack(anchor="w")
        self.verify_in = TextPanel(tab, "Mensagem assinada / dados", height=11)
        self.verify_in.pack(fill="both", expand=True, pady=8)
        self.verify_sig = TextPanel(tab, "Assinatura destacada (opcional)", height=5)
        self.verify_sig.pack(fill="x", pady=(0, 8))
        ttk.Button(tab, text="Verificar assinatura", style="Accent.TButton", command=self.do_verify).pack(anchor="e")
        self.verify_out = TextPanel(tab, "Resultado da verificação", height=8)
        self.verify_out.pack(fill="both", expand=False, pady=8)

    def _tab_sign_encrypt(self) -> None:
        tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab, text="Assinar + Criptografar")
        opts = ttk.Frame(tab)
        opts.pack(fill="x")
        opts.columnconfigure(1, weight=1)
        self.se_signer = self._signer_combo(opts, "Chave de assinatura:", 0)
        self.se_recipients = RecipientPicker(tab, "Destinatários")
        self.se_recipients.pack(fill="x", pady=6)
        self.se_in = TextPanel(tab, "Mensagem em claro", height=8, sensitive=True)
        self.se_in.pack(fill="both", expand=True, pady=8)
        ttk.Button(tab, text="Assinar e criptografar", style="Accent.TButton", command=self.do_sign_encrypt).pack(
            anchor="e"
        )
        self.se_out = TextPanel(tab, "Resultado", height=8)
        self.se_out.pack(fill="both", expand=True, pady=8)

    def _tab_files(self) -> None:
        tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab, text="Ficheiros")
        # Encrypt
        enc = ttk.LabelFrame(tab, text="Criptografar ficheiro", padding=8)
        enc.pack(fill="x", pady=(0, 8))
        enc.columnconfigure(1, weight=1)
        self.file_enc_path = tk.StringVar()
        ttk.Label(enc, text="Ficheiro:").grid(row=0, column=0, sticky="w")
        ttk.Entry(enc, textvariable=self.file_enc_path).grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(enc, text="Escolher…", command=lambda: self._pick_file(self.file_enc_path)).grid(row=0, column=2)
        self.file_enc_recipients = RecipientPicker(enc, "Destinatários")
        self.file_enc_recipients.grid(row=1, column=0, columnspan=3, sticky="ew", pady=6)
        ttk.Button(enc, text="Criptografar ficheiro", style="Accent.TButton", command=self.do_encrypt_file).grid(
            row=2, column=2, sticky="e"
        )

        # Decrypt
        dec = ttk.LabelFrame(tab, text="Descriptografar ficheiro", padding=8)
        dec.pack(fill="x", pady=8)
        dec.columnconfigure(1, weight=1)
        self.file_dec_path = tk.StringVar()
        ttk.Label(dec, text="Ficheiro:").grid(row=0, column=0, sticky="w")
        ttk.Entry(dec, textvariable=self.file_dec_path).grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(dec, text="Escolher…", command=lambda: self._pick_file(self.file_dec_path)).grid(row=0, column=2)
        ttk.Button(dec, text="Descriptografar ficheiro", style="Accent.TButton", command=self.do_decrypt_file).grid(
            row=1, column=2, sticky="e", pady=6
        )

        # Sign
        sig = ttk.LabelFrame(tab, text="Assinar ficheiro", padding=8)
        sig.pack(fill="x", pady=8)
        sig.columnconfigure(1, weight=1)
        self.file_sign_path = tk.StringVar()
        ttk.Label(sig, text="Ficheiro:").grid(row=0, column=0, sticky="w")
        ttk.Entry(sig, textvariable=self.file_sign_path).grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(sig, text="Escolher…", command=lambda: self._pick_file(self.file_sign_path)).grid(row=0, column=2)
        self.file_sign_key = self._signer_combo(sig, "Chave:", 1)
        ttk.Button(sig, text="Assinar (detach .sig)", style="Accent.TButton", command=self.do_sign_file).grid(
            row=2, column=2, sticky="e", pady=6
        )

        # Verify
        ver = ttk.LabelFrame(tab, text="Verificar assinatura de ficheiro", padding=8)
        ver.pack(fill="x", pady=8)
        ver.columnconfigure(1, weight=1)
        self.file_verify_path = tk.StringVar()
        self.file_verify_sig = tk.StringVar()
        ttk.Label(ver, text="Ficheiro:").grid(row=0, column=0, sticky="w")
        ttk.Entry(ver, textvariable=self.file_verify_path).grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(ver, text="Escolher…", command=lambda: self._pick_file(self.file_verify_path)).grid(row=0, column=2)
        ttk.Label(ver, text="Assinatura (.sig, opcional):").grid(row=1, column=0, sticky="w")
        ttk.Entry(ver, textvariable=self.file_verify_sig).grid(row=1, column=1, sticky="ew", padx=6)
        ttk.Button(ver, text="Escolher…", command=lambda: self._pick_file(self.file_verify_sig)).grid(row=1, column=2)
        ttk.Button(ver, text="Verificar ficheiro", style="Accent.TButton", command=self.do_verify_file).grid(
            row=2, column=2, sticky="e", pady=6
        )

        # Sign+Encrypt file
        se = ttk.LabelFrame(tab, text="Assinar + criptografar ficheiro", padding=8)
        se.pack(fill="x", pady=8)
        se.columnconfigure(1, weight=1)
        self.file_se_path = tk.StringVar()
        ttk.Label(se, text="Ficheiro:").grid(row=0, column=0, sticky="w")
        ttk.Entry(se, textvariable=self.file_se_path).grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(se, text="Escolher…", command=lambda: self._pick_file(self.file_se_path)).grid(row=0, column=2)
        self.file_se_signer = self._signer_combo(se, "Assinatura:", 1)
        self.file_se_recipients = RecipientPicker(se, "Destinatários")
        self.file_se_recipients.grid(row=2, column=0, columnspan=3, sticky="ew", pady=6)
        ttk.Button(
            se, text="Assinar + criptografar", style="Accent.TButton", command=self.do_sign_encrypt_file
        ).grid(row=3, column=2, sticky="e")

        ttk.Label(
            tab,
            text="Nunca sobrescreve o original automaticamente. Destino via diálogo; confirma se já existir.",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=8)

    def _tab_keys(self) -> None:
        tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab, text="Chaves")

        manager = ttk.LabelFrame(tab, text="Gerenciamento de chaves", padding=10)
        manager.pack(fill="x", pady=(0, 8))
        ttk.Label(
            manager,
            text="Encontre chaves já existentes no computador, crie uma nova, ou faça backup — "
            "sempre com fingerprint completo como identificador.",
            style="Muted.TLabel",
            wraplength=920,
        ).pack(anchor="w", pady=(0, 8))

        row1 = ttk.Frame(manager)
        row1.pack(fill="x", pady=2)
        ttk.Button(
            row1,
            text="Procurar chaves existentes",
            style="Accent.TButton",
            command=self.do_discover_keys,
        ).pack(side="left", padx=(0, 6))
        ttk.Button(row1, text="Procurar em uma pasta…", command=self.do_discover_in_folder).pack(
            side="left", padx=2
        )
        ttk.Button(row1, text="Criar nova chave", command=self.do_generate).pack(side="left", padx=2)
        ttk.Button(row1, text="Restaurar chave de backup…", command=self.do_restore_backup).pack(
            side="left", padx=2
        )

        row2 = ttk.Frame(manager)
        row2.pack(fill="x", pady=(8, 0))
        ttk.Button(
            row2,
            text="Copiar chave pública",
            style="Accent.TButton",
            command=self.do_copy_public_key,
        ).pack(side="left", padx=(0, 6))
        ttk.Button(row2, text="Exportar chave pública…", command=self.do_export_public).pack(
            side="left", padx=2
        )
        ttk.Button(row2, text="Backup da chave privada…", command=self.do_export_secret).pack(
            side="left", padx=2
        )
        ttk.Button(
            row2,
            text="Backup privado protegido…",
            command=self.do_export_secret_protected,
        ).pack(side="left", padx=2)

        mine = ttk.LabelFrame(tab, text="Minhas chaves (keyring GnuPG)", padding=6)
        mine.pack(fill="both", expand=True, pady=(0, 8))

        cols = (
            "nome",
            "email",
            "fingerprint",
            "tipo",
            "algo",
            "tamanho",
            "criada",
            "expira",
            "disp",
        )
        headings = {
            "nome": "Nome",
            "email": "E-mail",
            "fingerprint": "Fingerprint",
            "tipo": "Tipo",
            "algo": "Algoritmo",
            "tamanho": "Tamanho",
            "criada": "Criação",
            "expira": "Expiração",
            "disp": "Disponibilidade",
        }
        self.keys_tree = ttk.Treeview(mine, columns=cols, show="headings", height=10)
        for c in cols:
            self.keys_tree.heading(c, text=headings[c])
            width = 280 if c == "fingerprint" else (90 if c in {"algo", "tamanho", "criada", "expira"} else 120)
            self.keys_tree.column(c, width=width, stretch=c in {"nome", "fingerprint", "disp"})
        scroll = ttk.Scrollbar(mine, command=self.keys_tree.yview)
        self.keys_tree.configure(yscrollcommand=scroll.set)
        self.keys_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        # Compatibilidade com código que ainda consulta pub_tree/sec_tree
        self.pub_tree = self.keys_tree
        self.sec_tree = self.keys_tree

        actions = ttk.Frame(tab)
        actions.pack(fill="x", pady=(0, 6))
        ttk.Button(actions, text="Importar ficheiro…", command=self.do_import_file).pack(side="left", padx=2)
        ttk.Button(actions, text="Importar do painel ↓", command=self.do_import_paste).pack(side="left", padx=2)
        ttk.Button(actions, text="Atualizar lista", command=self.refresh_keys).pack(side="right", padx=2)

        self.key_io = TextPanel(
            tab,
            "Área para importar chave pública (ou ver exportação pública — nunca material privado)",
            height=7,
        )
        self.key_io.pack(fill="both", expand=True)

    def _reload_key_trees(self) -> None:
        tree = getattr(self, "keys_tree", None)
        if tree is None:
            return
        tree.delete(*tree.get_children())
        # Unificar por fingerprint: preferir entrada com privada
        by_fp: dict[str, KeyInfo] = {}
        for key in self.pub_keys:
            by_fp[key.fingerprint_normalized] = key
        for key in self.sec_keys:
            by_fp[key.fingerprint_normalized] = key
        for key in sorted(by_fp.values(), key=lambda k: (k.name or "", k.email or "", k.fingerprint_normalized)):
            has_priv = bool(key.is_secret or key.has_secret)
            tree.insert(
                "",
                "end",
                iid=key.fingerprint_normalized,
                values=(
                    key.name,
                    key.email,
                    key.fingerprint_display,
                    "Pública + privada" if has_priv else "Pública",
                    key.algo,
                    key.length,
                    key.created,
                    key.expires,
                    key.availability_label,
                ),
            )

    def _pick_file(self, var: tk.StringVar) -> None:
        path = filedialog.askopenfilename(title="Escolher ficheiro")
        if path:
            var.set(path)

    @staticmethod
    def _iid_to_fingerprint(raw: str) -> str:
        if ":" in raw:
            prefix, rest = raw.split(":", 1)
            if prefix in {"pub", "sec"} or prefix.startswith("d"):
                return normalize_fingerprint(rest)
        return normalize_fingerprint(raw)

    def _selected_tree_fingerprint(self) -> Optional[str]:
        tree = getattr(self, "keys_tree", None)
        if tree is not None:
            sel = tree.selection()
            if sel:
                return self._iid_to_fingerprint(sel[0])
        messagebox.showwarning(APP_TITLE, "Selecione uma chave na lista.")
        return None

    def _resolve_public_fingerprint(self, *, quiet: bool = False) -> Optional[str]:
        """Fingerprint da chave pública a partilhar: seleção → única privada → única pública."""
        tree = getattr(self, "keys_tree", None)
        if tree is not None:
            sel = tree.selection()
            if sel:
                return self._iid_to_fingerprint(sel[0])
        if len(self.sec_keys) == 1:
            return self.sec_keys[0].fingerprint_normalized
        if len(self.pub_keys) == 1:
            return self.pub_keys[0].fingerprint_normalized
        if not quiet:
            if not self.pub_keys and not self.sec_keys:
                messagebox.showwarning(APP_TITLE, "Não há chaves no keyring para copiar.")
            else:
                messagebox.showwarning(
                    APP_TITLE,
                    "Selecione a chave na aba Chaves\n"
                    "(há mais do que uma disponível).",
                )
                try:
                    self.notebook.select(getattr(self, "_keys_tab_index", "end"))
                except tk.TclError:
                    pass
        return None

    def _suggested_key_basename(self, fingerprint: str) -> str:
        key = self.service.get_key(fingerprint) or self.service.get_key(fingerprint, secret=True)
        if key and key.name:
            slug = "".join(ch.lower() if ch.isalnum() else "-" for ch in key.name).strip("-")
            slug = "-".join(part for part in slug.split("-") if part)[:40]
            if slug:
                return slug
        return normalize_fingerprint(fingerprint)[-16:].lower()

    def _ask_output_path(self, title: str, initial: str, defaultextension: str = ".asc") -> Optional[str]:
        path = filedialog.asksaveasfilename(
            title=title,
            defaultextension=defaultextension,
            initialfile=initial,
        )
        if not path:
            return None
        if not confirm_overwrite(path):
            return None
        return path

    def show_diagnostics(self) -> None:
        env = self.service.check_gpg_environment()
        messagebox.showinfo(
            APP_TITLE,
            "Diagnóstico GnuPG\n\n"
            f"Executável: {env.gpg_path}\n"
            f"Versão: {env.version}\n"
            f"Home: {env.gnupg_home}\n"
            f"Keyring: {'OK' if env.keyring_ok else 'FALHA'}\n"
            f"gpg-agent: {'OK' if env.agent_ok else 'não confirmado'}\n\n"
            + "\n".join(env.details),
        )

    # ---------- actions ----------

    def do_encrypt(self) -> None:
        recipients = self.enc_recipients.selected()
        msg = self.enc_in.get()
        if not msg.strip():
            messagebox.showwarning(APP_TITLE, "Escreva a mensagem.")
            return
        if not self.confirm_recipients(recipients):
            return
        result = self.service.encrypt(msg, recipients=[k.fingerprint_normalized for k in recipients])
        if result.ok:
            self.enc_out.set(result.data)
            self.enc_in.clear()
        self.show_result(result, "Mensagem criptografada.")

    def do_decrypt(self) -> None:
        data = self.dec_in.get().strip()
        if not data:
            messagebox.showwarning(APP_TITLE, "Cole a mensagem criptografada.")
            return
        result = self.service.decrypt(data)
        if result.ok:
            self.dec_out.set(result.data)
        self.show_result(result, "Mensagem descriptografada.")

    def do_sign(self) -> None:
        key = self._selected_signer(self.sign_key)
        msg = self.sign_in.get()
        if not key:
            messagebox.showwarning(APP_TITLE, "Selecione a chave de assinatura.")
            return
        if not msg.strip():
            messagebox.showwarning(APP_TITLE, "Escreva a mensagem.")
            return
        if not self.confirm_signer(key):
            return
        mode = self.sign_mode.get()
        result = self.service.sign(
            msg,
            keyid=key.fingerprint_normalized,
            clearsign=(mode == "clearsign"),
            detach=(mode == "detach"),
        )
        if result.ok:
            self.sign_out.set(result.data)
            if mode != "detach":
                self.sign_in.clear()
        self.show_result(result, "Mensagem assinada.")

    def do_verify(self) -> None:
        data = self.verify_in.get().strip()
        sig = self.verify_sig.get().strip() or None
        if not data:
            messagebox.showwarning(APP_TITLE, "Cole a mensagem assinada.")
            return
        result = self.service.verify(data, signature=sig)
        self.verify_out.set(result.message)
        self.set_status(result.message.splitlines()[0], result.ok)

    def do_sign_encrypt(self) -> None:
        signer = self._selected_signer(self.se_signer)
        recipients = self.se_recipients.selected()
        msg = self.se_in.get()
        if not signer:
            messagebox.showwarning(APP_TITLE, "Selecione a chave de assinatura.")
            return
        if not msg.strip():
            messagebox.showwarning(APP_TITLE, "Escreva a mensagem.")
            return
        if not self.confirm_recipients(recipients, signer=signer):
            return
        result = self.service.encrypt(
            msg,
            recipients=[k.fingerprint_normalized for k in recipients],
            sign_key=signer.fingerprint_normalized,
        )
        if result.ok:
            self.se_out.set(result.data)
            self.se_in.clear()
        self.show_result(result, "Mensagem assinada e criptografada.")

    def do_encrypt_file(self) -> None:
        path = self.file_enc_path.get().strip()
        recipients = self.file_enc_recipients.selected()
        if not path:
            messagebox.showwarning(APP_TITLE, "Escolha o ficheiro.")
            return
        if not self.confirm_recipients(recipients):
            return
        out = self._ask_output_path("Salvar ficheiro criptografado", Path(path).name + ".asc")
        if not out:
            return
        result = self.service.encrypt_file(
            path, recipients=[k.fingerprint_normalized for k in recipients], output=out
        )
        self.show_result(result, f"Ficheiro criptografado:\n{out}")

    def do_decrypt_file(self) -> None:
        path = self.file_dec_path.get().strip()
        if not path:
            messagebox.showwarning(APP_TITLE, "Escolha o ficheiro.")
            return
        suggested = Path(path).name
        if suggested.endswith(".asc"):
            suggested = suggested[:-4]
        elif suggested.endswith(".gpg"):
            suggested = suggested[:-4]
        out = self._ask_output_path("Salvar ficheiro descriptografado", suggested, defaultextension="")
        if not out:
            return
        result = self.service.decrypt_file(path, output=out)
        self.show_result(result, f"Ficheiro descriptografado:\n{out}")

    def do_sign_file(self) -> None:
        path = self.file_sign_path.get().strip()
        key = self._selected_signer(self.file_sign_key)
        if not path or not key:
            messagebox.showwarning(APP_TITLE, "Escolha o ficheiro e a chave.")
            return
        if not self.confirm_signer(key):
            return
        out = self._ask_output_path("Salvar assinatura", Path(path).name + ".sig", defaultextension=".sig")
        if not out:
            return
        result = self.service.sign_file(path, output=out, keyid=key.fingerprint_normalized, detach=True)
        self.show_result(result, f"Assinatura salva:\n{out}")

    def do_verify_file(self) -> None:
        path = self.file_verify_path.get().strip()
        if not path:
            messagebox.showwarning(APP_TITLE, "Escolha o ficheiro.")
            return
        sig = self.file_verify_sig.get().strip() or None
        result = self.service.verify_file(path, signature_path=sig)
        messagebox.showinfo(APP_TITLE, result.message)
        self.set_status(result.message.splitlines()[0], result.ok)

    def do_sign_encrypt_file(self) -> None:
        path = self.file_se_path.get().strip()
        signer = self._selected_signer(self.file_se_signer)
        recipients = self.file_se_recipients.selected()
        if not path or not signer:
            messagebox.showwarning(APP_TITLE, "Escolha o ficheiro e a chave de assinatura.")
            return
        if not self.confirm_recipients(recipients, signer=signer):
            return
        out = self._ask_output_path("Salvar ficheiro assinado+criptografado", Path(path).name + ".asc")
        if not out:
            return
        result = self.service.encrypt_file(
            path,
            recipients=[k.fingerprint_normalized for k in recipients],
            output=out,
            sign_key=signer.fingerprint_normalized,
        )
        self.show_result(result, f"Ficheiro assinado e criptografado:\n{out}")

    def do_import_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Importar chave",
            filetypes=[("Chaves PGP", "*.asc *.pgp *.gpg *.key"), ("Todos", "*.*")],
        )
        if not path:
            return
        # Pré-aviso se parecer privada
        try:
            head = Path(path).read_text(encoding="utf-8", errors="ignore")[:200]
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Não foi possível ler o ficheiro.\n{exc}")
            return
        if "PRIVATE KEY BLOCK" in head or "SECRET KEY BLOCK" in head:
            if not messagebox.askyesno(
                APP_TITLE,
                "Você está importando uma chave privada.\n"
                "Ela concede capacidade de assinar e/ou descriptografar\n"
                "conforme os recursos da chave.\n\nContinuar?",
                icon="warning",
            ):
                return
        result = self.service.import_key_file(path)
        self.key_io.set(result.message)
        self.refresh_keys()
        self.show_result(result, "Importação processada.")

    def do_import_paste(self) -> None:
        data = self.key_io.get().strip()
        if not data:
            messagebox.showwarning(APP_TITLE, "Cole a chave no painel.")
            return
        if "PRIVATE KEY BLOCK" in data or "SECRET KEY BLOCK" in data:
            if not messagebox.askyesno(
                APP_TITLE,
                "Você está importando uma chave privada.\n"
                "Ela concede capacidade de assinar e/ou descriptografar\n"
                "conforme os recursos da chave.\n\nContinuar?",
                icon="warning",
            ):
                return
        result = self.service.import_key(data)
        self.key_io.set(result.message)
        self.refresh_keys()
        self.show_result(result, "Importação processada.")

    def do_copy_public_key(self) -> None:
        fp = self._resolve_public_fingerprint()
        if not fp:
            return
        result = self.service.export_public(fp)
        if not result.ok or not result.data:
            self.show_result(result)
            return
        if "PRIVATE KEY BLOCK" in result.data or "SECRET KEY BLOCK" in result.data:
            messagebox.showerror(APP_TITLE, "Bloqueado: a exportação contém material privado.")
            return
        self.clipboard_clear()
        self.clipboard_append(result.data)
        try:
            self.update()
        except tk.TclError:
            pass
        if hasattr(self, "key_io"):
            self.key_io.set(result.data)
        messagebox.showinfo(
            APP_TITLE,
            "Chave pública copiada para o clipboard.\n\n"
            f"Fingerprint:\n{format_fingerprint(fp)}\n\n"
            "Cole no e-mail, no site ou envie a quem precise\n"
            "validar as suas assinaturas.",
        )
        self.set_status("Chave pública copiada para o clipboard", True)

    def do_discover_keys(self) -> None:
        self.set_status("A procurar chaves existentes (somente leitura)…")
        self.update_idletasks()
        result = self.service.discover_keys(include_keyring=True)
        self.set_status(result.message.splitlines()[0], result.ok)
        KeyDiscoveryDialog(self, result.discovered, title="Chaves encontradas")

    def do_discover_in_folder(self) -> None:
        folder = filedialog.askdirectory(title="Procurar chaves PGP nesta pasta")
        if not folder:
            return
        self.set_status("A varrer pasta (somente leitura)…")
        self.update_idletasks()
        result = self.service.discover_keys(include_keyring=False, directories=[folder])
        self.set_status(result.message.splitlines()[0], result.ok)
        KeyDiscoveryDialog(self, result.discovered, title=f"Chaves em {folder}")

    def import_discovered_key(self, item: DiscoveredKey) -> None:
        if item.already_in_keyring:
            messagebox.showinfo(
                APP_TITLE,
                "Esta chave já está disponível no seu keyring.\n\n"
                f"Fingerprint:\n{item.fingerprint_display}\n\n"
                "Não será importada novamente.",
            )
            return
        if not item.source or item.source.startswith("keyring:"):
            messagebox.showwarning(APP_TITLE, "Não há ficheiro de origem para importar.")
            return
        # source pode listar vários ficheiros separados por "; "
        path = item.source.split(";")[0].strip()
        if not Path(path).is_file():
            messagebox.showerror(APP_TITLE, f"Ficheiro de origem não encontrado:\n{path}")
            return

        detail = (
            "Você está prestes a importar:\n\n"
            f"Nome: {item.name or '(não informado)'}\n"
            f"E-mail: {item.email or '(não informado)'}\n"
            f"Fingerprint:\n{item.fingerprint_display}\n\n"
            f"Tipo:\n{item.type_label}\n\n"
            f"Origem:\n{path}\n\n"
            "Deseja importar esta chave?"
        )
        if item.has_private:
            detail = (
                "ATENÇÃO\n\n"
                "Esta chave contém material privado.\n\n"
                "Após a importação, ela poderá ser utilizada\n"
                "para assinar e/ou descriptografar conforme\n"
                "as capacidades da chave.\n\n"
                "Somente importe uma chave privada se você\n"
                "confia na origem do arquivo.\n\n" + detail
            )
            if not messagebox.askyesno(APP_TITLE, detail, icon="warning"):
                return
        elif not messagebox.askyesno(APP_TITLE, detail):
            return

        result = self.service.import_key_file(path)
        self.refresh_keys()
        if result.ok:
            self.key_io.set(result.message)
        self.show_result(result, "Importação processada.")

    def do_restore_backup(self) -> None:
        path = filedialog.askopenfilename(
            title="Restaurar chave de backup",
            filetypes=[("Chaves / backups PGP", "*.asc *.pgp *.gpg *.key"), ("Todos", "*.*")],
        )
        if not path:
            return
        found = self.service.inspect_key_file(path)
        if not found:
            messagebox.showerror(
                APP_TITLE,
                "O ficheiro não contém uma chave OpenPGP válida reconhecida pelo GnuPG.\n"
                "(extensão .asc/.key sozinha não basta — o conteúdo foi validado.)",
            )
            return
        item = found[0]
        if item.already_in_keyring:
            messagebox.showinfo(
                APP_TITLE,
                "Esta chave já está disponível no seu keyring.\n\n"
                f"{item.identity_block()}\n\n"
                "Importação ignorada para evitar duplicata.",
            )
            return
        self.import_discovered_key(item)

    def do_export_public(self) -> None:
        fp = self._selected_tree_fingerprint()
        if not fp:
            return
        base = self._suggested_key_basename(fp)
        out = self._ask_output_path("Salvar chave pública", f"{base}-public.asc")
        if not out:
            return
        result = self.service.save_export_file(fp, out, secret=False)
        if result.ok and result.data:
            self.key_io.set(result.data)
        self.show_result(result)

    def do_export_secret(self) -> None:
        fp = self._selected_tree_fingerprint()
        if not fp:
            return
        if not messagebox.askyesno(
            APP_TITLE,
            "ATENÇÃO — BACKUP DE CHAVE PRIVADA\n\n"
            "Você está prestes a exportar material privado.\n\n"
            "Quem obtiver este ficheiro poderá utilizar a chave\n"
            "de acordo com as suas capacidades, caso também consiga\n"
            "satisfazer a proteção por passphrase/configuração.\n\n"
            "NÃO envie este ficheiro por e-mail, chat ou serviços\n"
            "não confiáveis.\n\n"
            "Guarde o backup em armazenamento seguro.\n\n"
            f"Fingerprint:\n{format_fingerprint(fp)}\n\n"
            "Deseja continuar?",
            icon="warning",
        ):
            return
        base = self._suggested_key_basename(fp)
        out = self._ask_output_path(
            "Salvar backup da chave privada",
            f"{base}-private-backup.asc",
        )
        if not out:
            return
        # Nunca gravar automaticamente em secrets/ ou pasta do projeto sem escolha do utilizador
        result = self.service.save_export_file(fp, out, secret=True)
        # Garantir que o painel não recebe material privado
        if hasattr(self, "key_io") and "PRIVATE KEY" in (self.key_io.get() or ""):
            self.key_io.clear()
        self.show_result(result)

    def do_export_secret_protected(self) -> None:
        fp = self._selected_tree_fingerprint()
        if not fp:
            return
        if not messagebox.askyesno(
            APP_TITLE,
            "ATENÇÃO — BACKUP PRIVADO PROTEGIDO\n\n"
            "Será criado um ficheiro cifrado pelo GnuPG com a sua\n"
            "própria chave pública (MESSAGE).\n\n"
            "Para restaurar, precisará da chave privada correspondente\n"
            "e da autenticação no gpg-agent.\n\n"
            f"Fingerprint:\n{format_fingerprint(fp)}\n\n"
            "Deseja continuar?",
            icon="warning",
        ):
            return
        base = self._suggested_key_basename(fp)
        out = self._ask_output_path(
            "Salvar backup privado protegido",
            f"{base}-private-backup-protected.asc",
        )
        if not out:
            return
        result = self.service.save_export_file(fp, out, secret=True, protected=True)
        self.show_result(result)

    def do_generate(self) -> None:
        win = tk.Toplevel(self)
        win.title("Criar nova chave PGP")
        win.configure(bg=COLOR["bg"])
        win.transient(self)
        win.grab_set()
        frm = ttk.Frame(win, padding=16)
        frm.pack(fill="both", expand=True)
        frm.columnconfigure(1, weight=1)

        ttk.Label(frm, text="Criar nova chave PGP", style="Heading.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 10)
        )

        name = tk.StringVar()
        email = tk.StringVar()
        comment = tk.StringVar()
        algo = tk.StringVar(value="RSA 4096")
        expire = tk.StringVar(value="0")
        fields = (
            ("Nome:", name),
            ("E-mail:", email),
            ("Comentário:", comment),
        )
        for i, (lab, var) in enumerate(fields, start=1):
            ttk.Label(frm, text=lab).grid(row=i, column=0, sticky="w", pady=4)
            ttk.Entry(frm, textvariable=var).grid(row=i, column=1, sticky="ew", pady=4)

        ttk.Label(frm, text="Algoritmo:").grid(row=4, column=0, sticky="w", pady=4)
        algo_box = ttk.Combobox(frm, textvariable=algo, state="readonly", values=("RSA 4096",))
        algo_box.grid(row=4, column=1, sticky="ew", pady=4)
        ttk.Label(frm, text="Expiração (0=nunca, 1y…):").grid(row=5, column=0, sticky="w", pady=4)
        ttk.Entry(frm, textvariable=expire).grid(row=5, column=1, sticky="ew", pady=4)

        ttk.Label(frm, text="Frase-senha (GnuPG):").grid(row=6, column=0, sticky="w", pady=4)
        pw1 = ttk.Entry(frm, show="•")
        pw1.grid(row=6, column=1, sticky="ew", pady=4)
        ttk.Label(frm, text="Confirmar frase-senha:").grid(row=7, column=0, sticky="w", pady=4)
        pw2 = ttk.Entry(frm, show="•")
        pw2.grid(row=7, column=1, sticky="ew", pady=4)
        ttk.Label(
            frm,
            text="A frase-senha não é armazenada pela aplicação; só é enviada uma vez ao GnuPG.",
            style="Muted.TLabel",
            wraplength=420,
        ).grid(row=8, column=0, columnspan=2, sticky="w", pady=6)

        def submit() -> None:
            if not name.get().strip() or not email.get().strip():
                messagebox.showwarning(APP_TITLE, "Nome e e-mail são obrigatórios.", parent=win)
                return
            if pw1.get() != pw2.get():
                messagebox.showwarning(APP_TITLE, "Frases-senha não coincidem.", parent=win)
                return
            if len(pw1.get()) < 8:
                messagebox.showwarning(APP_TITLE, "Use pelo menos 8 caracteres.", parent=win)
                return
            if not messagebox.askyesno(
                APP_TITLE,
                f"Gerar RSA 4096 para:\n\nNome: {name.get().strip()}\nE-mail: {email.get().strip()}\n\nContinuar?",
                parent=win,
            ):
                return
            passphrase = pw1.get()
            win.destroy()
            self.set_status("Gerando chave RSA 4096 via GnuPG…")
            self.update_idletasks()
            result = self.service.generate_key(
                name=name.get().strip(),
                email=email.get().strip(),
                comment=comment.get().strip(),
                passphrase=passphrase,
                expire_date=expire.get().strip() or "0",
                key_type="RSA",
                key_length=4096,
            )
            del passphrase
            self.refresh_keys()
            if result.ok:
                self.key_io.set(result.message)
            self.show_result(result)

        btns = ttk.Frame(frm)
        btns.grid(row=9, column=0, columnspan=2, sticky="e", pady=12)
        ttk.Button(btns, text="Cancelar", command=win.destroy).pack(side="left", padx=4)
        ttk.Button(btns, text="Criar chave", style="Accent.TButton", command=submit).pack(side="left")
        fit_window(win, min_w=420, min_h=320, prefer_w=500, prefer_h=400, center=True)


class KeyDiscoveryDialog(tk.Toplevel):
    """Lista resultados de varredura (somente leitura) e permite importar com confirmação."""

    def __init__(self, app: PgpApp, items: list[DiscoveredKey], *, title: str = "Chaves encontradas") -> None:
        super().__init__(app)
        self.app = app
        self.items = items
        self.title(title)
        self.configure(bg=COLOR["bg"])
        self.transient(app)

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="Chaves encontradas", style="Heading.TLabel").pack(anchor="w")
        ttk.Label(
            frm,
            text="Varredura somente leitura — nada foi importado automaticamente. "
            "Selecione uma chave e importe se precisar.",
            style="Muted.TLabel",
            wraplength=920,
        ).pack(anchor="w", pady=(2, 8))

        cols = (
            "estado",
            "nome",
            "email",
            "tipo",
            "fingerprint",
            "algo",
            "tamanho",
            "criada",
            "expira",
            "origem",
            "disp",
        )
        headings = {
            "estado": "Estado",
            "nome": "Nome",
            "email": "E-mail",
            "tipo": "Tipo",
            "fingerprint": "Fingerprint",
            "algo": "Algo",
            "tamanho": "Bits",
            "criada": "Criação",
            "expira": "Expira",
            "origem": "Origem",
            "disp": "Disponibilidade",
        }
        wrap = ttk.Frame(frm)
        wrap.pack(fill="both", expand=True)
        # Altura da lista conforme quantidade de resultados
        row_count = max(4, min(18, len(items) if items else 4))
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings", height=row_count)
        for c in cols:
            self.tree.heading(c, text=headings[c])
            self.tree.column(c, width=220 if c in {"fingerprint", "origem"} else 100, stretch=c in {"origem", "fingerprint"})
        scroll = ttk.Scrollbar(wrap, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        self._by_iid: dict[str, DiscoveredKey] = {}
        for idx, item in enumerate(items):
            iid = f"d{idx}:{item.fingerprint_normalized}"
            self._by_iid[iid] = item
            self.tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    "✓ Já disponível" if item.already_in_keyring else "Nova",
                    item.name,
                    item.email,
                    item.type_label,
                    item.fingerprint_display,
                    item.algo,
                    item.length,
                    item.created,
                    item.expires,
                    item.source,
                    item.availability_label,
                ),
            )

        actions = ttk.Frame(frm)
        actions.pack(fill="x", pady=10)
        ttk.Button(actions, text="Importar chave selecionada", style="Accent.TButton", command=self._import).pack(
            side="left"
        )
        ttk.Button(actions, text="Fechar", command=self.destroy).pack(side="right")
        if not items:
            ttk.Label(frm, text="Nenhuma chave OpenPGP válida foi encontrada.", style="Muted.TLabel").pack(
                anchor="w"
            )

        prefer_h = 220 + row_count * 28
        fit_window(
            self,
            min_w=720,
            min_h=320,
            prefer_w=980,
            prefer_h=prefer_h,
            center=True,
        )

    def _import(self) -> None:
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning(APP_TITLE, "Selecione uma chave na lista.", parent=self)
            return
        item = self._by_iid.get(sel[0])
        if item is None:
            return
        self.app.import_discovered_key(item)
        # Atualizar estado visual após importação
        if item.fingerprint_normalized in self.app.service.keyring_fingerprints():
            item.already_in_keyring = True
            item.keyring_has_secret = self.app.service.keyring_fingerprints().get(
                item.fingerprint_normalized, False
            )
            self.tree.item(
                sel[0],
                values=(
                    "✓ Já disponível",
                    item.name,
                    item.email,
                    item.type_label,
                    item.fingerprint_display,
                    item.algo,
                    item.length,
                    item.created,
                    item.expires,
                    item.source,
                    item.availability_label,
                ),
            )


def main() -> None:
    os.umask(0o077)
    ensure_secrets_layout()
    app = PgpApp()
    app.mainloop()


if __name__ == "__main__":
    main()
