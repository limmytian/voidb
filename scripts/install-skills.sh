#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Install VoidB skills from this git checkout into the local skills directory.

Usage:
  scripts/install-skills.sh [--copy] [--force] [--dest PATH]

Defaults:
  - symlink each skills/<skill> directory
  - install into ${VOIDB_SKILLS_HOME:-$HOME/.config/voidb/skills}
  - refuse to overwrite an existing non-matching local skill

Options:
  --copy       Copy skill directories instead of symlinking them.
  --force      Replace existing local skills with the same names.
  --dest PATH  Install into PATH instead of the default skills dir.
  -h, --help   Show this help.
USAGE
}

mode="link"
force="0"
dest="${VOIDB_SKILLS_HOME:-$HOME/.config/voidb/skills}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --copy)
      mode="copy"
      shift
      ;;
    --force)
      force="1"
      shift
      ;;
    --dest)
      if [[ $# -lt 2 ]]; then
        echo "error: --dest requires a path" >&2
        exit 2
      fi
      dest="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
src_root="$repo_root/skills"

if [[ ! -d "$src_root" ]]; then
  echo "error: skill source directory not found: $src_root" >&2
  exit 1
fi

mkdir -p "$dest"

installed=0
for skill_dir in "$src_root"/*; do
  [[ -d "$skill_dir" ]] || continue
  [[ -f "$skill_dir/SKILL.md" ]] || continue

  skill_name="$(basename "$skill_dir")"
  target="$dest/$skill_name"

  if [[ -e "$target" || -L "$target" ]]; then
    if [[ "$mode" == "link" && -L "$target" ]]; then
      current="$(readlink "$target")"
      if [[ "$current" == "$skill_dir" ]]; then
        echo "ok: $skill_name already linked"
        installed=$((installed + 1))
        continue
      fi
    fi

    if [[ "$force" != "1" ]]; then
      echo "error: $target already exists; rerun with --force to replace it" >&2
      exit 1
    fi

    rm -rf -- "$target"
  fi

  if [[ "$mode" == "copy" ]]; then
    cp -R "$skill_dir" "$target"
    echo "copied: $skill_name"
  else
    ln -s "$skill_dir" "$target"
    echo "linked: $skill_name"
  fi

  installed=$((installed + 1))
done

echo "installed $installed skill(s) into $dest"
