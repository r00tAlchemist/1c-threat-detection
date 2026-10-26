#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Удаляет службу сборщика журнала 1С. Данные остаются, если не указан -Purge.
#>
param(
    [string] $InstallDir = "$env:ProgramData\1c-eventlog",
    [switch] $Purge                         # удалить и $InstallDir (события, checkpoint, логи)
)

$ErrorActionPreference = "Stop"

$ServiceId = "1c-shipper"

if (Get-Service $ServiceId -ErrorAction SilentlyContinue) {
    $ErrorActionPreference = "Continue"
    & "$InstallDir\$ServiceId.exe" stop 2>&1      | Out-Null
    & "$InstallDir\$ServiceId.exe" uninstall 2>&1 | Out-Host
    $ErrorActionPreference = "Stop"
}

if ($Purge) { Remove-Item $InstallDir -Recurse -Force }
Write-Host "Служба удалена"
