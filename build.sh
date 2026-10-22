#!/usr/bin/env bash
# Empacota PGP Desk como executável (PyInstaller) e instala atalho no Desktop.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

PYTHON="${DIR}/.venv/bin/python"
PIP="${DIR}/.venv/bin/pip"
PYINSTALLER="${DIR}/.venv/bin/pyinstaller"

# Recria o venv se estiver ausente ou partido (ex.: pasta movida de outro path).
if [[ ! -x "$PYTHON" ]] || ! "$PIP" -V >/dev/null 2>&1; then
  echo "A (re)criar ambiente virtual em .venv …"
  rm -rf .venv
  python3 -m venv .venv
fi

"$PIP" install -q -r requirements.txt pyinstaller pillow

# Regenera ícone se Pillow estiver disponível e o script existir
if [[ -f scripts/make_icon.py ]]; then
  "$PYTHON" scripts/make_icon.py
fi

NAME="PGP Desk"
DIST_DIR="$DIR/dist"
BUILD_DIR="$DIR/build"
EXE_NAME="pgp-desk"
ICON="$DIR/assets/pgp-desk.png"
DESKTOP_DIR="$(xdg-user-dir DESKTOP 2>/dev/null || echo "$HOME/Desktop")"

rm -rf "$BUILD_DIR" "$DIST_DIR/$EXE_NAME"

"$PYINSTALLER" \
  --noconfirm \
  --clean \
  --onefile \
  --windowed \
  --name "$EXE_NAME" \
  --icon "$ICON" \
  --add-data "assets:assets" \
  --hidden-import gnupg \
  app.py

chmod +x "$DIST_DIR/$EXE_NAME"

# Ícones no tema hicolor — necessários para a barra/dock do GNOME
ICON_THEME="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor"
for sz in 48 64 128 256 512; do
  mkdir -p "$ICON_THEME/${sz}x${sz}/apps"
  src="$DIR/assets/pgp-desk-${sz}.png"
  [[ -f "$src" ]] || src="$ICON"
  cp "$src" "$ICON_THEME/${sz}x${sz}/apps/pgp-desk.png"
done

write_desktop() {
  local dest="$1"
  cat > "$dest" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=${NAME}
Comment=Assinar, verificar, criptografar e gerir chaves PGP/GPG
Exec=${DIST_DIR}/${EXE_NAME}
Icon=${ICON}
Path=${DIR}
Terminal=false
Categories=Utility;Security;Encryption;
StartupNotify=true
StartupWMClass=Pgpdesk
EOF
  chmod +x "$dest"
  if command -v gio >/dev/null 2>&1; then
    gio set "$dest" metadata::trusted true 2>/dev/null || true
  fi
}

DESKTOP_FILE="$DESKTOP_DIR/PGP Desk.desktop"
APPS_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
mkdir -p "$APPS_DIR"
APPS_FILE="$APPS_DIR/pgp-desk.desktop"

write_desktop "$DESKTOP_FILE"
write_desktop "$APPS_FILE"

# GNOME/Nautilus: sem metadata::trusted o atalho vira ícone genérico de documento
if command -v gio >/dev/null 2>&1; then
  gio set "$DESKTOP_FILE" metadata::trusted true 2>/dev/null || true
  gio set "$APPS_FILE" metadata::trusted true 2>/dev/null || true
fi

# Atualiza cache de ícones / menu (GNOME dock usa ~/.local/share/applications)
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$APPS_DIR" 2>/dev/null || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -f "${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor" 2>/dev/null || true
fi

# Fixa na barra lateral (favoritos), se ainda não estiver
if command -v gsettings >/dev/null 2>&1; then
  "$PYTHON" - <<'PY' 2>/dev/null || true
import ast, subprocess
favs = subprocess.check_output(
    ["gsettings", "get", "org.gnome.shell", "favorite-apps"], text=True
).strip()
apps = ast.literal_eval(favs)
if "pgp-desk.desktop" not in apps:
    apps.append("pgp-desk.desktop")
    out = "[" + ", ".join(f"'{a}'" for a in apps) + "]"
    subprocess.check_call(["gsettings", "set", "org.gnome.shell", "favorite-apps", out])
PY
fi

echo ""
echo "Executável: $DIST_DIR/$EXE_NAME"
echo "Atalho:     $DESKTOP_FILE"
echo "Menu/Barra: $APPS_FILE"
echo "Pronto. Clique duas vezes em \"PGP Desk\" no Desktop."
