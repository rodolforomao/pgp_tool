#!/usr/bin/env bash
# Fluxo de branch/deploy:
#   branch = YYYYMMDDNN  (NN = sequência do dia, 01..)
#   tag    = X.XX.XXX    (major.minor.patch com zero-pad)
# Empurra para origin e regenera o binário (./build.sh).
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

REMOTE_URL="${REMOTE_URL:-https://github.com/rodolforomao/pgp_tool.git}"
VERSION_FILE="$DIR/VERSION"

die() { echo "erro: $*" >&2; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "comando em falta: $1"; }

need_cmd git
need_cmd date

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  cat <<EOF
Uso: ./deploy.sh [X.XX.XXX]

  Cria branch YYYYMMDDNN, grava VERSION, faz tag X.XX.XXX,
  faz merge em master (código mais atualizado), push e regenera o binário.

  Sem argumentos: incrementa o patch a partir da última tag
  (ou usa VERSION / 1.00.001 na primeira vez).

Remote: $REMOTE_URL
EOF
  exit 0
fi

[[ -d .git ]] || die "repositório Git inexistente — execute git init primeiro"

# Garante remote origin
if git remote get-url origin >/dev/null 2>&1; then
  git remote set-url origin "$REMOTE_URL"
else
  git remote add origin "$REMOTE_URL"
fi

# Branch estável onde fica o código mais atualizado (sempre master)
MAIN_BRANCH="master"

parse_version() {
  local v="$1"
  [[ "$v" =~ ^([0-9]+)\.([0-9]{2})\.([0-9]{3})$ ]] || return 1
  MAJOR="${BASH_REMATCH[1]}"
  MINOR="${BASH_REMATCH[2]}"
  PATCH="${BASH_REMATCH[3]}"
}

format_version() {
  printf '%d.%02d.%03d' "$1" "$((10#$2))" "$((10#$3))"
}

bump_patch() {
  local maj="$1" min="$2" pat="$3"
  pat=$((10#$pat + 1))
  if (( pat > 999 )); then
    pat=1
    min=$((10#$min + 1))
  fi
  if (( min > 99 )); then
    min=0
    maj=$((maj + 1))
  fi
  format_version "$maj" "$min" "$pat"
}

latest_tag_version() {
  git tag -l '[0-9]*.[0-9][0-9].[0-9][0-9][0-9]' --sort=-v:refname 2>/dev/null | head -1
}

# --- branch YYYYMMDDNN -------------------------------------------------------
today="$(date +%Y%m%d)"

next_branch_nn() {
  local max=0 b nn
  git fetch origin --prune 2>/dev/null || true

  while IFS= read -r b; do
    [[ "$b" =~ ^${today}([0-9]{2})$ ]] || continue
    nn=$((10#${BASH_REMATCH[1]}))
    (( nn > max )) && max=$nn
  done < <(git for-each-ref --format='%(refname:short)' refs/heads)

  while IFS= read -r b; do
    b="${b#origin/}"
    [[ "$b" =~ ^${today}([0-9]{2})$ ]] || continue
    nn=$((10#${BASH_REMATCH[1]}))
    (( nn > max )) && max=$nn
  done < <(git for-each-ref --format='%(refname:short)' refs/remotes/origin 2>/dev/null || true)

  printf '%02d' $((max + 1))
}

BRANCH="${today}$(next_branch_nn)"

# --- tag X.XX.XXX ------------------------------------------------------------
if [[ -n "${1:-}" ]]; then
  parse_version "$1" || die "versão inválida '$1' (esperado X.XX.XXX, ex.: 1.00.001)"
  TAG="$(format_version "$MAJOR" "$MINOR" "$PATCH")"
else
  last="$(latest_tag_version || true)"
  if [[ -n "$last" ]]; then
    parse_version "$last" || die "tag existente inválida: $last"
    TAG="$(bump_patch "$MAJOR" "$MINOR" "$PATCH")"
  elif [[ -f "$VERSION_FILE" ]]; then
    base="$(tr -d '[:space:]' < "$VERSION_FILE")"
    parse_version "$base" || die "VERSION inválido: $base"
    TAG="$(format_version "$MAJOR" "$MINOR" "$PATCH")"
  else
    TAG="1.00.001"
  fi
fi

if git rev-parse "$TAG" >/dev/null 2>&1; then
  die "tag já existe: $TAG"
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  die "há alterações por commitar — faça commit (ou stash) antes do deploy"
fi

if [[ -z "$(git rev-parse --verify HEAD 2>/dev/null || true)" ]]; then
  die "nenhum commit em HEAD"
fi

echo "Branch: $BRANCH"
echo "Tag:    $TAG"
echo "Main:   $MAIN_BRANCH"
echo "Remote: $REMOTE_URL"

# Deploy parte sempre do código estável
git checkout "$MAIN_BRANCH"
git pull --ff-only origin "$MAIN_BRANCH" 2>/dev/null || true

git checkout -b "$BRANCH"

printf '%s\n' "$TAG" > "$VERSION_FILE"
if ! git diff --quiet -- "$VERSION_FILE"; then
  git add "$VERSION_FILE"
  git commit -m "release: $TAG (branch $BRANCH)"
fi

git tag -a "$TAG" -m "Release $TAG"

echo "A enviar branch e tag…"
git push -u origin "$BRANCH"
git push origin "refs/tags/$TAG"

echo "A consolidar em $MAIN_BRANCH…"
git checkout "$MAIN_BRANCH"
git merge --ff-only "$BRANCH"
git push origin "$MAIN_BRANCH"

echo "A regenerar binário…"
"$DIR/build.sh"

echo ""
echo "Deploy concluído."
echo "  branch  $BRANCH"
echo "  tag     $TAG"
echo "  master  $MAIN_BRANCH (atualizada; checkout ativo)"
echo "  binário dist/pgp-desk"
