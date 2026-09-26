# ============================================================
#  Remove Acer bloatware (Care Center, UEIP, Jumpstart, ConfigMgr)
#  Run: double-click or from terminal. Confirm the UAC prompt.
#  Quick Access Service (Fn keys) and DriverSetupUtility are KEPT.
#  Log: tools\acer_cleanup_log.txt
# ============================================================

$logPath = Join-Path $PSScriptRoot 'acer_cleanup_log.txt'
function Log($msg) {
    $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $msg
    Write-Host $line
    Add-Content -Path $logPath -Value $line
}

# --- Self-elevation (UAC) ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Requesting administrator rights (UAC)...'
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

Set-Content -Path $logPath -Value ('=== Acer bloatware cleanup === ' + (Get-Date))
$ErrorActionPreference = 'Continue'

# --- 1. Disable scheduled tasks ---
$tasks = @(
    @{ Name = 'ACCBackgroundApplication'; Path = '\' },
    @{ Name = 'Quick Access';             Path = '\' },
    @{ Name = 'UbtFrameworkService';      Path = '\' },
    @{ Name = 'UEIPInvitation';           Path = '\' },
    @{ Name = 'AcerJumpstartTask';        Path = '\Oem\' }
)
Log '=== 1. Disabling scheduled tasks ==='
foreach ($t in $tasks) {
    try {
        $task = Get-ScheduledTask -TaskName $t.Name -TaskPath $t.Path -ErrorAction Stop
        Disable-ScheduledTask -InputObject $task -ErrorAction Stop | Out-Null
        Log "  DISABLED: $($t.Path)$($t.Name)"
    } catch {
        Log "  SKIP ($($t.Name)): $($_.Exception.Message)"
    }
}

# --- 2. Stop and disable Care Center service ---
Log '=== 2. Acer services ==='
foreach ($s in @('ACCSvc')) {
    if (Get-Service $s -ErrorAction SilentlyContinue) {
        Stop-Service $s -Force -ErrorAction SilentlyContinue
        Set-Service $s -StartupType Disabled -ErrorAction SilentlyContinue
        $st = (Get-Service $s -ErrorAction SilentlyContinue).Status
        Log "  $s -> $st (Startup: Disabled)"
    }
}

# --- 3. Uninstall Acer MSI programs ---
Log '=== 3. Uninstalling Acer MSI programs ==='
$msi = @(
    @{ Code = '{AFB52E98-7597-4484-9202-58F0FD3512ED}'; Name = 'Care Center Service' },
    @{ Code = '{E9495FD3-F73D-4D33-A104-047F9E8BE6C7}'; Name = 'User Experience Improvement Program Service' },
    @{ Code = '{0C5ED25A-B8D1-4E71-BFCB-6B370A4EA19C}'; Name = 'Acer Jumpstart' },
    @{ Code = '{22165EE8-F79D-4400-A6FB-8E35391B8BEF}'; Name = 'Acer Configuration Manager' }
)
foreach ($m in $msi) {
    Log "  Removing $($m.Name) ..."
    $p = Start-Process msiexec.exe -ArgumentList "/x $($m.Code) /qn /norestart" -Wait -PassThru
    Log "    exit code: $($p.ExitCode) (0 = ok, 1605 = already absent)"
}

# --- 4. Kill leftover processes ---
Log '=== 4. Leftover processes ==='
Get-Process -Name 'ACCStd','ACCSvc','ACCApp','hermes','TriggerFramework','UEIPOOBECheck' -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue

# --- 5. Final verification ---
Log '=== 5. Verification ==='
Log '-- Processes:'
$procs = Get-Process | Where-Object { $_.Name -match 'ACC|Acer|hermes|UEIP|Trigger' }
if ($procs) { $procs | ForEach-Object { Log "    $($_.Name) (PID $($_.Id))" } } else { Log '    (no Acer processes)' }
Log '-- Services:'
Get-Service | Where-Object { $_.Name -match 'ACC|QALSvc' } | ForEach-Object { Log "    $($_.Name): $($_.Status) / $($_.StartType)" }
Log '-- Installed Acer programs:'
$paths = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
$left = Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object { $_.Publisher -match 'Acer' -and $_.DisplayName }
if ($left) { $left | ForEach-Object { Log "    $($_.DisplayName)" } } else { Log '    (no Acer programs left)' }

Log '=== DONE. Quick Access (Fn keys) was NOT touched. ==='
Read-Host 'Press Enter to close this window...'