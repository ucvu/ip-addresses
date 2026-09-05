$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvDir = Join-Path $ProjectDir ".venv"
if (-not (Test-Path -LiteralPath $VenvDir)) {
    python -m venv $VenvDir
}
$Python = Join-Path $VenvDir "Scripts\python.exe"
& $Python -m pip install --upgrade pip
& $Python -m pip install -r (Join-Path $ProjectDir "requirements.txt")

$Desktop = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $Desktop "Netcraze WireGuard.lnk"
$Shell = New-Object -ComObject WScript.Shell
$Shortcut = $Shell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $ProjectDir 'run_web.ps1')`""
$Shortcut.WorkingDirectory = $ProjectDir
$Shortcut.Description = "Локальная панель управления WireGuard на роутерах Netcraze"
$Shortcut.Save()
Write-Host "Готово. Ярлык создан: $ShortcutPath"
