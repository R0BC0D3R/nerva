# A-B-B-A over the real daemon's miner, v13 on a mainnet database copy.
#
# Traps this script works around, all of which have already cost a run:
#  - The daemon reads EOF on stdin and exits if its streams are redirected,
#    which looks exactly like a crash. So it is launched with Start-Process and
#    its own console, and everything comes back over RPC.
#  - The --start-mining command-line flag silently does not start the miner.
#    The start_mining RPC does, and returns a status that can be checked.
#  - The hashrate is bistable, roughly 300 vs 600 H/s for the same binary, and
#    one A-B-B-A came back with the two baselines 98% apart because of it. The
#    suspect is large pages: allocate_hugepage falls back to malloc silently
#    when physical memory is too fragmented to hand out 2 MB runs, and an 8 MB
#    scratchpad per thread on 4 KB pages is a different workload. The miner
#    logs which tier it got, but only at MGINFO, which --log-level 0 hides. So
#    every run now runs at --log-level 1, writes its own log, and the tier is
#    parsed back out and reported next to the number. A run that did not get
#    huge pages is retried, and if it still cannot, the run is reported with
#    the tier it had rather than quietly averaged in.
#  - mining_status.speed is hashes in the last 2-second merge window, not a
#    moving average. Settled it holds to about +/-4%, so a short averaged
#    window is enough, but the settle itself has to be long: a fresh daemon
#    reads high for the first couple of minutes before stepping down.
#  - Anything written to the output stream inside a PowerShell function becomes
#    part of that function's return value, so progress uses Write-Host.

param(
    [int]$Threads = 12,
    [int]$SettleSeconds = 150,
    [int]$Samples = 12,
    [int]$SampleGap = 5,
    [int]$MaxAttempts = 3
)

$ErrorActionPreference = 'Stop'

$Base = 'D:\Claude\v6miner\ab\nervad-base.exe'
$Fold = 'D:\Claude\v6miner\ab\nervad-fold.exe'
$DataDir = 'D:\Claude\nerva-dbcheck'
$LogDir = 'C:\Users\SUPERD~1\AppData\Local\Temp\claude\d--Code-Crypto-Nerva-nerva\04afb0ce-e4fb-4d82-80b0-019aa04aec62\scratchpad\ablogs'
$Port = 18999
# Any valid mainnet address parses. Nothing is paid out: the chain copy is
# stale and offline, and at mainnet difficulty no block is ever found.
$Addr = 'NV1aMtARDQjK8j7XeoQ66S7XQe5ZS8CX92XqXmJxSZMpSDf2i11NQyqgHzghmRsDHR1LwYv3bEnE3VoqqbmyRdrR2MMBfdXvY'

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$script:runSeq = 0

function Invoke-Daemon($path, $body) {
    try {
        return Invoke-RestMethod -Uri "http://127.0.0.1:$Port/$path" -Method Post `
            -Body $body -ContentType 'application/json' -TimeoutSec 15
    } catch {
        return $null
    }
}

function Stop-Daemons {
    Invoke-Daemon 'stop_daemon' '{}' | Out-Null
    $deadline = (Get-Date).AddSeconds(45)
    while ((Get-Date) -lt $deadline) {
        if (-not (Get-Process -Name 'nervad-base','nervad-fold' -ErrorAction SilentlyContinue)) {
            Start-Sleep -Seconds 2
            return
        }
        Start-Sleep -Seconds 2
    }
    Get-Process -Name 'nervad-base','nervad-fold' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 4
}

# One attempt: start, mine, read the page tier, sample. Returns $null when the
# daemon did not get huge pages and a retry is still allowed.
function Invoke-Attempt($exe, $label, $requireHuge) {
    $script:runSeq++
    $log = Join-Path $LogDir ("run{0:d2}.log" -f $script:runSeq)
    $dargs = @(
        '--data-dir', $DataDir,
        '--offline',
        '--rpc-bind-port', $Port,
        '--p2p-bind-port', '18998',
        '--zmq-rpc-bind-port', '18997',
        '--log-file', $log,
        '--log-level', '1'
    )
    Start-Process -FilePath $exe -ArgumentList $dargs -WindowStyle Minimized | Out-Null

    $info = $null
    $deadline = (Get-Date).AddMinutes(5)
    while ((Get-Date) -lt $deadline) {
        $info = Invoke-Daemon 'get_info' '{}'
        if ($info -ne $null -and $info.height -gt 0) { break }
        Start-Sleep -Seconds 3
    }
    if ($info -eq $null) { Stop-Daemons; throw "$label never answered RPC" }

    # v13 only applies between HF13 and the HF14 placeholder. Outside that the
    # miner would be running a different algorithm entirely.
    if ($info.height -lt 4320000 -or $info.height -ge 4500000) {
        Stop-Daemons
        throw "height $($info.height) is not in the v13 range 4320000 to 4499999"
    }

    $body = '{"miner_address":"' + $Addr + '","threads_count":' + $Threads +
            ',"do_background_mining":false,"ignore_battery":true}'
    $r = Invoke-Daemon 'start_mining' $body
    if ($r -eq $null -or $r.status -ne 'OK') {
        Stop-Daemons
        throw "$label start_mining failed: $($r.status)"
    }

    # The tier line appears once the first miner thread has a template.
    $tier = 'unknown'
    $deadline = (Get-Date).AddSeconds(90)
    while ((Get-Date) -lt $deadline) {
        $hit = Select-String -Path $log -Pattern 'Mining scratchpads on (.+)$' -ErrorAction SilentlyContinue |
               Select-Object -Last 1
        if ($hit) { $tier = $hit.Matches[0].Groups[1].Value.Trim(); break }
        Start-Sleep -Seconds 3
    }

    if ($requireHuge -and $tier -ne 'huge pages') {
        Stop-Daemons
        Write-Host ("  {0,-18} attempt discarded, tier was '{1}', retrying" -f $label, $tier)
        Start-Sleep -Seconds 10
        return $null
    }

    Start-Sleep -Seconds $SettleSeconds

    $readings = @()
    for ($i = 0; $i -lt $Samples; $i++) {
        $ms = Invoke-Daemon 'mining_status' '{}'
        if ($ms -ne $null -and $ms.active -and $ms.speed -gt 0) { $readings += [double]$ms.speed }
        Start-Sleep -Seconds $SampleGap
    }

    Stop-Daemons

    if ($readings.Count -lt 8) { throw "$label gave only $($readings.Count) readings" }
    $stats = $readings | Measure-Object -Average -Minimum -Maximum
    Write-Host ("  {0,-18} n={1,2}  mean {2,6:F1}  min {3,4:F0}  max {4,4:F0} H/s   [{5}]" -f `
        $label, $readings.Count, $stats.Average, $stats.Minimum, $stats.Maximum, $tier)
    return $stats.Average
}

function Measure-Build($exe, $label) {
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $v = Invoke-Attempt $exe $label ($attempt -lt $MaxAttempts)
        if ($v -ne $null) { return $v }
    }
    throw "$label never produced a reading"
}

Write-Host "v13 daemon miner, $Threads threads, offline, mainnet DB copy at height 4424749"
Write-Host "A = baseline, B = fused pad init"
Write-Host "settle ${SettleSeconds}s, then $Samples samples ${SampleGap}s apart, averaged"
Write-Host "page tier recorded per run; a run without huge pages is retried"
Write-Host ""

Stop-Daemons

$a1 = Measure-Build $Base 'A1  baseline'
$b1 = Measure-Build $Fold 'B1  fused'
$b2 = Measure-Build $Fold 'B2  fused'
$a2 = Measure-Build $Base 'A2  baseline'

$drift = ($a2 - $a1) / $a1 * 100.0
$am = ($a1 + $a2) / 2.0
$bm = ($b1 + $b2) / 2.0
$d = ($bm - $am) / $am * 100.0

Write-Host ""
Write-Host ("A drift across the pair: {0:+0.0;-0.0}%" -f $drift) -NoNewline
if ([Math]::Abs($drift) -gt 2.0) {
    Write-Host "   (over 2%, treat this run as void)"
} else {
    Write-Host "   (within tolerance)"
}
Write-Host ("baseline mean {0:F1} H/s   fused mean {1:F1} H/s   delta {2:+0.0;-0.0}%" -f $am, $bm, $d)
