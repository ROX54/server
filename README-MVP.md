# Cyber Garden Security Workflow — MVP

## Быстрый старт

Для запуска локальной веб-панели используйте [README-DASHBOARD.md](README-DASHBOARD.md):

- Windows: `START-DASHBOARD.bat`
- Linux/macOS: `./START-DASHBOARD.sh`
- Браузер: `http://127.0.0.1:8765`

Без интерфейса анализаторы можно запустить так:

```bash
python3 security_workflow.py
python3 validate_results.py
```

На Windows с установленным Python используйте `py -3` вместо `python3`. Для собственного безопасного учебного проекта передайте путь к проекту первым аргументом `security_workflow.py` и укажите отдельный выходной каталог через `--out`.

Результаты находятся в `security-report/`:

- `findings.json` — обязательный JSON с массивом `findings`;
- `report.md` — читаемый отчёт;
- `validation.md` — сверка с учебным эталоном.

## Проверка на предоставленном учебном наборе

Актуальные метрики находятся в `security-report/validation.md`. Дополнительные advisory SCA сверяются отдельно и до проверки исключаются из FP, Precision и F1.

Тесты этапа 1 запускаются командой `python3 -m unittest -v test_contest_pipeline`. Kotlin/Spring и Gradle проверяются статически с помощью локальных правил. Справочник охватывает заданные Maven advisory и версии с числовыми компонентами.
