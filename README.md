# 1c-threat-detection

Сборщик журнала регистрации 1С:Предприятие 8.3 и правила Sigma для обнаружения атак на 1С. Подходит для любого SIEM.

1С — самая распространённая ERP в России. Журнал регистрации она пишет в своём закрытом формате, и готовых правил для SIEM под него почти нет. Сборщик переводит журнал в обычный JSON, а правила ловят подбор паролей, создание пользователей, изменение конфигурации и запуск команд из внешних обработок.

## Как это работает

```
1С:Предприятие ──► 1Cv8Log\*.lgf, *.lgp
                        │
                        ▼
              onec_shipper.py   (служба Windows)
                        │
                        ▼
        C:\ProgramData\1c-eventlog\events.json   (JSON, одно событие на строку)
                        │
                        ▼
        агент вашего SIEM читает файл  ──►  SIEM  ◄──  правила из sigma/
```

В проекте две части, и они не зависят друг от друга:

1. **Сборщик** ставится на сервер 1С и пишет события в `events.json`. Про SIEM он ничего не знает.
2. **Правила** из `sigma/` конвертируются под нужный SIEM через [sigma-cli](https://github.com/SigmaHQ/sigma-cli).

До SIEM файл довозит агент, который у вас уже стоит: Wazuh, Elastic, RuSIEM, Splunk, MaxPatrol и другие.

## Правила

| Правило | Что ловит | Severity | MITRE ATT&CK |
|---|---|---|---|
| `1c_bruteforce.yml` — неудачный вход | неудачный вход в базу | low | T1110 |
| `1c_bruteforce.yml` — подбор пароля (корреляция) | ≥5 неудачных входов за 60 с | high | T1110.001 |
| `1c_user_created.yml` | создан пользователь информационной базы | high | T1136.001 |
| `1c_config_update.yml` | изменена конфигурация базы | medium | T1505 |
| `1c_shell_spawn.yml` | процесс 1С запустил `cmd`, `powershell`, `mshta` и т. п. — выполнение кода из внешней обработки | high | T1059 |
| `1c_shell_output_redirect.yml` | процесс 1С запустил `cmd` с выводом в файл (`whoami > %TEMP%\res.txt`) — обработка выполняет команду и читает результат | critical | T1059.003 |
| `sigma-correlation/1c_shell_child.yml` | в оболочке, запущенной из 1С, выполнена команда (`whoami`, `ipconfig`…), связь по LogonId за 10 мин | high | T1059 |
| `sigma-correlation/1c_login_after_bruteforce.yml` | успешный вход в течение 2 мин после подбора пароля | critical | T1110, T1078 |

Правила из `sigma/` проходят `sigma check` и конвертируются в Splunk, Elastic ES|QL и EQL.

Правило «вход после подбора пароля» лежит отдельно, в `sigma-correlation/`: это цепочка корреляций (`temporal_ordered`), а бэкенды Splunk и ES|QL её пока не конвертируют. Если ваш SIEM умеет такие корреляции, подключайте его. Если нет, переложите логику в нативное правило: в `rules/wazuh/` это правило 100106. То же для `1c_shell_child.yml`: в Wazuh это правило 100109.

`1c_shell_spawn.yml` работает не по журналу 1С, а по событиям создания процессов Windows: открытие внешней обработки журнал регистрации не фиксирует, видно только то, что обработка запустила. При работе через веб-клиент серверный код выполняется в пуле приложений IIS, поэтому в списке родителей есть `w3wp.exe`. Нужен Sysmon (Event ID 1) или аудит создания процессов с командной строкой (Event ID 4688). Включить аудит на сервере 1С:

```powershell
auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

В домене то же самое лучше задать групповой политикой. Нативные правила Wazuh (100107–100109) используют 4688 из журнала Security, который агент Wazuh собирает по умолчанию.

Для Wazuh есть готовый нативный набор в `rules/wazuh/`, проверенный на реальных атаках в лабе.

## Установка

### 1. Сборщик — на сервер или ПК с 1С

**Что нужно заранее**

- Windows 10/11 или Windows Server 2016+.
- Python 3.10 или новее. Если его нет:
  ```powershell
  winget install Python.Python.3.12
  ```
- Права администратора.

**Шаг 1. Скачайте проект**

Через git:

```powershell
git clone https://github.com/r00tAlchemist/1c-threat-detection
cd 1c-threat-detection
```

Или без git: **Code → Download ZIP** на странице репозитория, распакуйте архив и перейдите в папку `1c-threat-detection` в PowerShell.

**Шаг 2. Найдите каталог журнала регистрации**

Это папка `1Cv8Log`, в ней лежит файл `1Cv8.lgf`.

| Тип базы | Где искать |
|---|---|
| Файловая | `<каталог базы>\1Cv8Log` (каталог базы виден в списке баз окна запуска 1С) |
| Серверная | `<каталог srvinfo>\reg_1541\<GUID базы>\1Cv8Log`, обычно `C:\Program Files\1cv8\srvinfo\...` |

**Шаг 3. Подставьте свои значения и запустите установку**

Откройте PowerShell **от имени администратора**, перейдите в папку проекта и замените значения в первых двух строках на свои:

```powershell
$LogDir   = "C:\Users\user\Documents\InfoBase\1Cv8Log"   # каталог 1Cv8Log из шага 2
$InfoBase = "accounting"                                  # имя базы, попадёт в поле ib

powershell -ExecutionPolicy Bypass -File .\install\install.ps1 -LogDir $LogDir -InfoBase $InfoBase
```

`-ExecutionPolicy Bypass` нужен, потому что Windows по умолчанию запрещает запуск скриптов PowerShell. Политика меняется только для этого запуска, системные настройки не трогаются.

**Шаг 4. Проверьте**

```powershell
Get-Service 1c-shipper
Get-Content C:\ProgramData\1c-eventlog\events.json -Tail 5 -Encoding UTF8
```

Служба должна быть в статусе `Running`. После любого входа в базу в `events.json` появятся новые строки. Если служба не запустилась, причина будет в `C:\ProgramData\1c-eventlog\logs`.

Служба стартует вместе с Windows и перезапускается при сбое.

**Дополнительные параметры**

Нужны редко, их можно добавить в конец команды установки.

| Параметр | По умолчанию | Зачем |
|---|---|---|
| `-InstallDir` | `C:\ProgramData\1c-eventlog` | другая папка для сборщика и `events.json` |
| `-Python` | ищется автоматически | путь к `python.exe`, если Python не найден сам или их несколько |
| `-WinSWPath` | скачивается с GitHub | путь к заранее скачанному `WinSW-x64.exe`, если на сервере нет интернета |

**Обновление и удаление**

Для обновления скачайте новую версию проекта и запустите установку ещё раз с теми же значениями. Удаление:

```powershell
powershell -ExecutionPolicy Bypass -File .\install\uninstall.ps1
```

С флагом `-Purge` удалятся и накопленные события.

### 2. Подключение к SIEM

Настройте агент своего SIEM на чтение `C:\ProgramData\1c-eventlog\events.json` в формате JSON (одно событие на строку). Готовые конфиги:

| SIEM | Сбор | Правила |
|---|---|---|
| Wazuh | `collectors/wazuh-agent.xml` → в `ossec.conf` агента | `rules/wazuh/1c_rules.xml` → `/var/ossec/etc/rules/` на менеджере |
| Elastic | `collectors/filebeat.yml` (не проверен в лабе) | `sigma convert -t esql sigma/` |
| Splunk | Universal Forwarder, `sourcetype=_json` | `sigma convert -t splunk sigma/` |
| Другие | любой агент, читающий JSON-файл | `sigma convert -t <backend> sigma/` |

## Формат события

```json
{"integration":"1c","ib":"demo","ts":"2026-10-26T18:40:30","ev":{"id":"_$Session$_.AuthenticationError","level":"error"},"user":{"name":"Администратор"},"computer":"WS01","app":"1CV8","session":2,"comment":""}
```

| Поле | |
|---|---|
| `integration` | всегда `1c` — для фильтра на стороне SIEM |
| `ev.id` | системный ID события 1С (`_$Session$_.Authentication`, `_$User$_.New`, …) — по нему пишутся правила |
| `ev.level` | `information` / `warning` / `error` / `note` |
| `ev.meta`, `ev.data` | объект метаданных и представление данных (если есть) |
| `user.name`, `computer`, `app`, `session` | кто, откуда, каким клиентом, номер сеанса |
| `ts` | локальное время сервера 1С, без часового пояса |

Событие лежит в `ev`, а не в `event`: имя `event` во многих SIEM зарезервировано (ECS, Wazuh), и объект на его месте ломает маппинг индекса.

## Ограничения

- Только текстовый формат журнала (`.lgf` + `.lgp`). SQLite-формат (`.lgd`) не поддерживается.
- Одна служба — одна информационная база.
- При обычном входе 1С сначала пробует аутентификацию ОС и при неудаче пишет `_$Session$_.AuthenticationError` — так же, как при неверном пароле. Поэтому одиночные ошибки входа шумят, а порог брутфорса (5 за 60 с) подобран с запасом.
- Проверено на 1С 8.3.16 (учебная версия), Windows 11, Wazuh 4.12.

## Проверка

Сделайте 5+ неверных входов в базу за минуту — в SIEM сработают правила неудачного входа и брутфорса.

Для правил запуска команд создайте внешнюю обработку с командой `ЗапуститьПриложение("cmd /c whoami")`, откройте её в 1С и выполните — сработают `1c_shell_spawn.yml` и `1c_shell_child.yml`. С командой `cmd /c "whoami > %TEMP%\res.txt"` дополнительно сработает `1c_shell_output_redirect.yml`.

## Структура

```
parser/onec_shipper.py     сборщик: журнал 1С → JSON
install/                   install.ps1, uninstall.ps1 — служба Windows (WinSW)
sigma/                     правила для любого SIEM
sigma-correlation/         цепочки корреляций (нужна поддержка в бэкенде)
rules/wazuh/               нативные правила Wazuh
collectors/                примеры конфигов агентов
```

## Лицензия

[MIT](LICENSE). Sigma-правила можно свободно использовать в своём SIEM.
