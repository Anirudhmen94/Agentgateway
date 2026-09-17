# Stop the process listening on 127.0.0.1:8000 (Windows PowerShell)
param(
    [string]$BindHost = "127.0.0.1",
    [int]$Port = 8000
)
$ErrorActionPreference = "Stop"

$pids = @()
$conns = Get-NetTCPConnection -LocalAddress $BindHost -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($conns) {
    $pids = $conns | Select-Object -ExpandProperty OwningProcess -Unique
}

if (-not $pids) {
    $pattern = "$BindHost:$Port"
    netstat -ano | Select-String -Pattern $pattern | ForEach-Object {
        $parts = ($_.Line -split "\s+") | Where-Object { $_ }
        if ($parts.Length -ge 5 -and $parts[-1] -match "^\d+$") {
            $pids += [int]$parts[-1]
        }
    }
    $pids = $pids | Select-Object -Unique
}

if (-not $pids) {
    Write-Host "Nothing listening on ${BindHost}:${Port}."
    exit 0
}

foreach ($procId in $pids) {
    if ($procId -le 4) { continue }
    Write-Host "Stopping PID $procId on ${BindHost}:${Port}"
    Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
}
