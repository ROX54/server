# CyberGarden AI Server

Локальный Python API для статического анализа учебного Repair Desk. Сервер содержит собственные SECRET, SAST и SCA, исполнитель workflow, расписание, историю, AI Analysis и уведомления webhook.

## Запуск

Требуется Python 3.10+. Склонируйте [server](https://github.com/ROX54/server) и [client](https://github.com/ROX54/client) в соседние каталоги. В каталоге `server` запустите `START-DASHBOARD.bat` на Windows или `./START-DASHBOARD.sh` на Linux и macOS. Dashboard доступен на [127.0.0.1:8765](http://127.0.0.1:8765).

Сервер ищет frontend в `../client`. Для другого расположения задайте `CYBERGARDEN_CLIENT_DIR` в окружении или локальном `.env`. API можно использовать отдельно от интерфейса. Например, `GET /api/findings` возвращает конкурсные результаты.

## Проверка и настройки

- Проверьте анализаторы командами `python security_workflow.py` и `python validate_results.py`. JSON, Markdown и метрики находятся в `security-report/`.
- Для автотестов с соседним checkout клиента запустите `python -m unittest -v`.
- AI и webhook настраиваются через локальный `.env` по [.env.example](.env.example). [Руководство Dashboard](README-DASHBOARD.md) описывает Workflow Builder и демонстрационный приёмник.
- [Спецификация конкурсного отчёта](docs/submission-format.md) и учебный эталон входят в серверный репозиторий. Repair Desk содержит намеренно уязвимые примеры и синтетические данные для статического сканирования. Dashboard по умолчанию слушает loopback.
