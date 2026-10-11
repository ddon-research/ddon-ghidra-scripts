#!/usr/bin/env bash
# Create the editor environment used by .vscode/settings.json: ./venv with pyghidra and
# ghidra-stubs, plus the `ghidra` -> `ghidra-stubs` link that makes `import ghidra` resolve.
#
# Usage: ./setup-venv.sh [--force]
#   --force  delete and recreate an existing ./venv
#
# Headless runs do not use this venv: run_ghidra_analysis.sh starts Ghidra's own PyGhidra
# (PYGHIDRA_RUN in ../.env). This venv only serves IntelliSense, type checking, and tests.
set -o errexit
set -o nounset
set -o pipefail

die() { echo "ERROR: $*" >&2; exit 2; }
for cmd in uv; do
  command -v "$cmd" >/dev/null 2>&1 || die "required command '$cmd' not found (https://docs.astral.sh/uv/)"
done

cd "$(dirname "${BASH_SOURCE[0]}")"
if [[ -e venv ]]; then
  [[ ${1:-} == --force ]] || die "./venv already exists (pass --force to recreate it)"
  rm -rf ./venv
fi

# Ghidra 11.4.2's PyGhidra supports CPython 3.12; ghidra-stubs must match the Ghidra version.
VIRTUAL_ENV='' uv venv --python 3.12 venv
VIRTUAL_ENV='' uv pip install --python venv -r requirements.txt

site=venv/Lib/site-packages
[[ -d $site ]] || site=$(echo venv/lib/python3.*/site-packages)
[[ -d "$site/ghidra-stubs" ]] || die "ghidra-stubs not installed in $site"
if [[ ! -e "$site/ghidra" ]]; then
  if command -v cygpath >/dev/null 2>&1; then
    # Windows: a directory junction needs neither admin rights nor developer mode.
    # MSYS_NO_PATHCONV keeps MSYS from rewriting the /c and /J switches into drive paths.
    MSYS_NO_PATHCONV=1 cmd.exe /c mklink /J "$(cygpath -aw "$site/ghidra")" "$(cygpath -aw "$site/ghidra-stubs")" >/dev/null
  else
    ln -s ghidra-stubs "$site/ghidra"
  fi
fi
[[ -e "$site/ghidra/__init__.pyi" || -d "$site/ghidra" ]] || die "failed to link $site/ghidra"
echo "venv ready: $(venv/Scripts/python.exe -c 'import sys; print(sys.version.split()[0])' 2>/dev/null \
  || venv/bin/python -c 'import sys; print(sys.version.split()[0])')"
