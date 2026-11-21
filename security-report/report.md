# Отчёт статического анализа

Всего находок: **15**

| Категория | Серьёзность | Файл | Место / зависимость | Описание | Рекомендация |
|---|---|---|---|---|---|
| SAST | HIGH | src/main/kotlin/lab/repairdesk/config/RepairCors.kt | credentialed-cors, строка 13–14 | Политика CORS допускает произвольный origin с учётными данными. | Перечислить доверенные origin или отключить передачу credentials. |
| SAST | HIGH | src/main/kotlin/lab/repairdesk/config/RepairSecurity.kt | route-authorization, строка 18 | Публичное правило для маршрута предшествует более строгому правилу, которое также его покрывает. | Уточнить порядок и область правил доступа и проверить политику для маршрута. |
| SAST | HIGH | src/main/kotlin/lab/repairdesk/integration/SupplierHttpsClient.kt | tls-verification, строка 13 | HTTPS-клиент допускает соединение без штатной проверки имени хоста. | Использовать стандартную проверку имени хоста и доверенную цепочку сертификатов. |
| SAST | CRITICAL | src/main/kotlin/lab/repairdesk/repair/RepairLookupController.kt | sql-injection, строка 13–14 | SQL собирается с подстановкой динамического значения перед передачей в JDBC. | Передавать значения отдельными параметрами JDBC. |
| SAST | HIGH | src/main/kotlin/lab/repairdesk/repair/RepairTicketReader.kt | object-authorization, строка 10–11 | Объект выбирается по идентификатору запроса без видимого ограничения по владельцу. | Ограничить выборку идентификатором текущего пользователя или проверить права на объект. |
| SCA | MEDIUM | build.gradle.kts | commons-net:commons-net:3.8.0 (CVE-2021-37533) | Разрешённая версия входит в диапазон уязвимых версий из локального справочника. | Выбрать исправленную версию из справочника и обновить lockfile. |
| SCA | MEDIUM | build.gradle.kts | org.apache.commons:commons-compress:1.25.0 (CVE-2024-25710) | Разрешённая версия входит в диапазон уязвимых версий из локального справочника. | Выбрать исправленную версию из справочника и обновить lockfile. |
| SCA | CRITICAL | build.gradle.kts | org.apache.commons:commons-text:1.9 (CVE-2022-42889) | Разрешённая версия входит в диапазон уязвимых версий из локального справочника. | Выбрать исправленную версию из справочника и обновить lockfile. |
| SCA | HIGH | build.gradle.kts | org.json:json:20230227 (CVE-2023-5072) | Разрешённая версия входит в диапазон уязвимых версий из локального справочника. | Выбрать исправленную версию из справочника и обновить lockfile. |
| SCA | HIGH | build.gradle.kts | org.jsoup:jsoup:1.14.1 (CVE-2021-37714) | Разрешённая версия входит в диапазон уязвимых версий из локального справочника. | Выбрать исправленную версию из справочника и обновить lockfile. |
| SECRET | HIGH | src/main/kotlin/lab/repairdesk/integration/DepotStatusClient.kt | secret-fallback, строка 8 | При отсутствии настройки используется встроенный секрет. | Удалить значение по умолчанию и явно обработать отсутствие настройки. |
| SECRET | HIGH | src/main/kotlin/lab/repairdesk/integration/PartsImportSettings.kt | password, строка 4 | Встроенный пароль хранится в файле проекта. | Загружать пароль из защищённой конфигурации. |
| SECRET | HIGH | src/main/kotlin/lab/repairdesk/integration/QuoteRequest.kt | api-key, строка 7 | Ключ API задан строковым литералом. | Хранить ключ в защищённой конфигурации и заменить опубликованный ключ. |
| SECRET | HIGH | src/main/kotlin/lab/repairdesk/integration/WarrantyHeaders.kt | recoverable-token, строка 7–10 | Bearer-токен собирается из строковых литералов в исходниках. | Получать токен из защищённого хранилища. |
| SECRET | HIGH | src/main/resources/application.yml | configuration-token, строка 13 | В файле задан токен авторизации. | Загружать токен из защищённого хранилища. |
