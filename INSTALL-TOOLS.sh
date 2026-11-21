#!/usr/bin/env bash
set -euo pipefail
# Installs user-level tools where possible. Review package-manager prompts.
if command -v brew >/dev/null 2>&1; then
  brew install gitleaks osv-scanner
elif command -v go >/dev/null 2>&1; then
  go install github.com/gitleaks/gitleaks/v8@latest
  go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest
else
  echo 'Install Go or use your OS package manager for Gitleaks and OSV-Scanner.' >&2
fi
python3 -m pip install --user semgrep
printf '\nThen verify: gitleaks version; semgrep --version; osv-scanner --version\n'
printf 'Optional AI (Ollama): export OPENAI_BASE_URL=http://localhost:11434/v1\n'
printf 'Set OPENAI_MODEL to your Ollama model name. No API key is needed for localhost.\n'
