# Экспериментальные анализаторы и AI

См. `README-DASHBOARD.md`. Кратко:

- Windows: `./INSTALL-TOOLS.ps1`
- Linux/macOS: `./INSTALL-TOOLS.sh`
- AI: скопировать `.env.example` в `.env`, настроить OpenAI-compatible API или локальный Ollama.

Для отдельного экспериментального запуска используйте external_scanners.py. Статусы Gitleaks, Semgrep и OSV-Scanner сохраняются в security-report/external-findings.json. Конкурсный запуск из Dashboard использует только собственные анализаторы.

AI-объяснение доступно через кнопку «Объяснить с помощью AI» в карточке находки.
