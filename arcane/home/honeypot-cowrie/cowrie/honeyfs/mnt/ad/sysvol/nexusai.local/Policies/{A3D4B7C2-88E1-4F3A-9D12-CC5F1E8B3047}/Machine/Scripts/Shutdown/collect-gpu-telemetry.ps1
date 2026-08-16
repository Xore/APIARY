# Collect GPU node telemetry on graceful shutdown
# GPO: GPU Nodes - Baseline Hardening  Scope: Machine Shutdown
# Owner: NEXUSAI\svc-mlflow

$gpuInfo = & nvidia-smi --query-gpu=name,memory.total,memory.used,temperature.gpu,utilization.gpu --format=csv,noheader,nounits 2>$null
$payload = @{
    host      = $env:COMPUTERNAME
    timestamp = (Get-Date -Format o)
    gpus      = ($gpuInfo -split "`n" | Where-Object { $_ } | ForEach-Object {
        $f = $_ -split ','
        @{ name=$f[0].Trim(); mem_total=$f[1].Trim(); mem_used=$f[2].Trim(); temp=$f[3].Trim(); util=$f[4].Trim() }
    })
} | ConvertTo-Json -Depth 4

Invoke-RestMethod -Uri 'http://monitor.nexusai.local:9100/api/gpu/shutdown' `
    -Method Post -Body $payload -ContentType 'application/json' -TimeoutSec 10 | Out-Null
