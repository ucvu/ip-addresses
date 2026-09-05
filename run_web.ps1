$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvPython = Join-Path $ProjectDir ".venv\Scripts\python.exe"
$Python = if (Test-Path -LiteralPath $VenvPython) { $VenvPython } else { "python" }
$HostName = if ($env:NETCRAZE_WEB_HOST) { $env:NETCRAZE_WEB_HOST } else { "127.0.0.1" }
$Port = if ($env:NETCRAZE_WEB_PORT) { $env:NETCRAZE_WEB_PORT } else { "8765" }
Start-Process "http://127.0.0.1:$Port"
& $Python -m webapp
