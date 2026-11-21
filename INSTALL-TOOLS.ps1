$ErrorActionPreference = 'Stop'
Write-Host 'Installing Cyber Garden external security scanners...' -ForegroundColor Green
if (-not (Get-Command go -ErrorAction SilentlyContinue)) { Write-Warning 'Go is not installed. Install Go first: https://go.dev/dl/' }
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { Write-Warning 'winget not found; install Gitleaks manually from https://github.com/gitleaks/gitleaks/releases' }
else { winget install --id Gitleaks.Gitleaks --exact --accept-package-agreements --accept-source-agreements }
python -m pip install --user semgrep
if (Get-Command go -ErrorAction SilentlyContinue) {
  go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest
}
Write-Host 'Close and reopen the terminal, then run: gitleaks version; semgrep --version; osv-scanner --version' -ForegroundColor Cyan
Write-Host 'AI is optional. For a local model, install Ollama and pull a model, then set OPENAI_BASE_URL=http://localhost:11434/v1 and OPENAI_MODEL to that model.'
