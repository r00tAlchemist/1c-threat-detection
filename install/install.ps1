#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Устанавливает сборщик журнала регистрации 1С как службу Windows (через WinSW).

.EXAMPLE
    .\install.ps1 -LogDir "C:\Users\user\Documents\InfoBase\1Cv8Log" -InfoBase demo
    .\install.ps1 -LogDir "D:\1C\Accounting\1Cv8Log" -InfoBase accounting
#>
param(
    [Parameter(Mandatory)] [string] $LogDir,  # каталог 1Cv8Log информационной базы
    [string] $InfoBase   = "demo",            # имя базы для поля "ib"
    [string] $InstallDir = "$env:ProgramData\1c-eventlog",
    [string] $Python,                         # путь к python.exe, по умолчанию ищется сам
    [string] $WinSWPath                       # локальный WinSW-x64.exe для установки без интернета
)

$ErrorActionPreference = "Stop"

$ServiceId   = "1c-shipper"
$WinSWUrl    = "https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe"
$WinSWSha256 = "05B82D46AD331CC16BDC00DE5C6332C1EF818DF8CEEFCD49C726553209B3A0DA"

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }

# Windows PowerShell 5.1 при "Stop" превращает stderr внешней программы в исключение.
function Native([string] $Exe, [string[]] $Arguments) {
    $ErrorActionPreference = "Continue"
    & $Exe @Arguments 2>&1 | Out-Host
    $LASTEXITCODE
}

function Find-Python {
    $candidates = @()
    if (Get-Command py -ErrorAction SilentlyContinue) {
        $ErrorActionPreference = "Continue"
        $candidates += (& py -3 -c "import sys; print(sys.executable)" 2>$null)
    }
    $candidates += Get-Command python -All -ErrorAction SilentlyContinue |
        Where-Object { $_.Source -notlike "*\WindowsApps\*" } | ForEach-Object { $_.Source }
    foreach ($p in $candidates) {
        if ($p -and (Test-Path $p)) {
            & $p -c "import sys; sys.exit(sys.version_info < (3, 10))" 2>$null
            if ($LASTEXITCODE -eq 0) { return $p }
        }
    }
    throw "Не найден Python 3.10+. Установите его (winget install Python.Python.3.12) или укажите -Python."
}

# ---- проверки ----
$LogDir = (Resolve-Path $LogDir).Path
if (-not (Test-Path "$LogDir\1Cv8.lgf")) {
    throw "В $LogDir нет 1Cv8.lgf. Поддерживается только текстовый формат журнала (.lgf/.lgp), SQLite (.lgd) - нет."
}
if ($Python) { $Python = (Resolve-Path $Python).Path } else { $Python = Find-Python }
Step "Python: $Python"

# ---- файлы ----
Step "Установка в $InstallDir"
New-Item -ItemType Directory -Force $InstallDir | Out-Null
$exe = "$InstallDir\$ServiceId.exe"

if (Get-Service $ServiceId -ErrorAction SilentlyContinue) {
    Step "Служба уже есть, переустанавливаю"
    Native $exe stop      | Out-Null
    Native $exe uninstall | Out-Null
}

if (-not $WinSWPath) {
    $WinSWPath = "$env:TEMP\WinSW-x64.exe"
    Step "Скачиваю WinSW"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -UseBasicParsing $WinSWUrl -OutFile $WinSWPath
}
$hash = (Get-FileHash $WinSWPath -Algorithm SHA256).Hash
if ($hash -ne $WinSWSha256) { throw "SHA256 у WinSW не совпадает: $hash" }
Copy-Item $WinSWPath $exe -Force
Copy-Item "$PSScriptRoot\..\parser\onec_shipper.py" $InstallDir -Force
if (-not (Test-Path "$InstallDir\events.json")) { New-Item -ItemType File "$InstallDir\events.json" | Out-Null }

$esc = [Security.SecurityElement]
@"
<service>
  <id>$ServiceId</id>
  <name>Сборщик журнала регистрации 1С</name>
  <description>Пишет журнал регистрации 1С ($($esc::Escape($InfoBase))) в $InstallDir\events.json</description>
  <executable>$($esc::Escape($Python))</executable>
  <arguments>"$($esc::Escape("$InstallDir\onec_shipper.py"))"</arguments>
  <env name="ONEC_LOG_DIR" value="$($esc::Escape($LogDir))"/>
  <env name="ONEC_OUT_DIR" value="$($esc::Escape($InstallDir))"/>
  <env name="ONEC_IB" value="$($esc::Escape($InfoBase))"/>
  <env name="PYTHONUNBUFFERED" value="1"/>
  <env name="PYTHONUTF8" value="1"/>
  <startmode>Automatic</startmode>
  <onfailure action="restart" delay="10 sec"/>
  <resetfailure>1 hour</resetfailure>
  <stoptimeout>15 sec</stoptimeout>
  <logpath>$($esc::Escape("$InstallDir\logs"))</logpath>
  <log mode="roll-by-size">
    <sizeThreshold>10240</sizeThreshold>
    <keepFiles>5</keepFiles>
  </log>
</service>
"@ | Set-Content "$InstallDir\$ServiceId.xml" -Encoding UTF8

# ---- служба ----
Step "Регистрирую службу $ServiceId"
if ((Native $exe install) -ne 0) { throw "WinSW: не удалось установить службу" }
if ((Native $exe start) -ne 0)   { throw "WinSW: служба не запустилась, смотрите $InstallDir\logs" }

Start-Sleep 3
Get-Service $ServiceId | Format-Table Name, Status, StartType -AutoSize
Write-Host "События: $InstallDir\events.json   Логи: $InstallDir\logs"
